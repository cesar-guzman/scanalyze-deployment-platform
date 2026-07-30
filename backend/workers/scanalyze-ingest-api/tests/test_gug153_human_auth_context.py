"""Red contract tests for the GUG-153 human authorization snapshot.

The JWT verifier is mocked with synthetic, already-verified claims.  These tests
therefore exercise only the provider-to-``AuthContext`` adapter boundary; they
never parse a real token, call Cognito, or use customer data.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from app.auth import AuthContext, _resolve_cognito_auth
from app.errors import AppError


NOW = 1_800_000_000
SNAPSHOT_MAX_AGE_SECONDS = 300

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
FOREIGN_CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
FOREIGN_DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAY"

AUTHZ_SCHEMA_VERSION = "enterprise-authorization.v1"
SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
ROLE_CATALOG_VERSION = "enterprise-roles.v1"
POLICY_VERSION = "1.0.0"
POLICY_DIGEST = (
    "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
)
OTHER_POLICY_DIGEST = f"sha256:{'0' * 64}"
ASSURANCE_CLAIM = "custom:authentication_assurance"
PHISHING_RESISTANT_MFA = "phishing_resistant_mfa"

CANONICAL_ROLES = (
    "customer_admin",
    "document_operator",
    "document_reviewer",
    "auditor",
)


def _settings(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "env": "test",
        "auth_mode": "cognito_jwt",
        "cognito_user_pool_id": "us-east-1_SYNTHETIC",
        "cognito_region": "us-east-1",
        "cognito_allowed_token_uses": "access",
        "cognito_allowed_client_ids": "synthetic-spa-client",
        "tenant_claim_name": "custom:customerId",
        "deployment_claim_name": "custom:deployment_id",
        "scanalyze_deployment_customer_id": CUSTOMER_ID,
        "scanalyze_deployment_id": DEPLOYMENT_ID,
        "m2m_tenant_resolution": "disabled",
        "m2m_client_tenant_map": None,
        "m2m_client_identity_bindings_v1": None,
        "m2m_action_scope_sets_v1": None,
        "human_enterprise_authorization_enabled": True,
        "enterprise_authorization_schema_version": AUTHZ_SCHEMA_VERSION,
        "enterprise_scope_catalog_version": SCOPE_CATALOG_VERSION,
        "enterprise_role_catalog_version": ROLE_CATALOG_VERSION,
        "enterprise_policy_version": POLICY_VERSION,
        "enterprise_policy_digest": POLICY_DIGEST,
        "enterprise_membership_snapshot_max_age_seconds": SNAPSHOT_MAX_AGE_SECONDS,
        "enterprise_assurance_claim_name": ASSURANCE_CLAIM,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _claims(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "sub": "synthetic-human-subject",
        "username": "synthetic-human-user",
        "client_id": "synthetic-spa-client",
        "token_use": "access",
        "scope": "scanalyze.api.v1/read scanalyze.api.v1/write scanalyze.api.v1/admin",
        "custom:customerId": CUSTOMER_ID,
        "custom:deployment_id": DEPLOYMENT_ID,
        "principal_type": "user",
        "membership_state": "active",
        "role_id": "document_operator",
        "membership_version": "7",
        "authz_schema_version": AUTHZ_SCHEMA_VERSION,
        "scope_catalog_version": SCOPE_CATALOG_VERSION,
        "role_catalog_version": ROLE_CATALOG_VERSION,
        "policy_version": POLICY_VERSION,
        "policy_digest": POLICY_DIGEST,
        "iat": NOW - 30,
        "auth_time": NOW - 60,
        ASSURANCE_CLAIM: PHISHING_RESISTANT_MFA,
    }
    values.update(overrides)
    return values


def _resolve(
    *,
    claims: dict[str, Any] | None = None,
    settings: SimpleNamespace | None = None,
    legacy_tenant_header: str | None = None,
) -> AuthContext:
    with (
        patch("app.auth._verify_cognito_jwt", return_value=claims or _claims()),
        patch("app.auth.time.time", return_value=NOW),
    ):
        return _resolve_cognito_auth(
            token="synthetic-signed-access-token",
            settings=settings or _settings(),
            legacy_tenant_header=legacy_tenant_header,
            request_path="/api/v1/documents/document-synthetic-0001",
        )


def _assert_forbidden(call) -> AppError:
    with pytest.raises(AppError) as captured:
        call()
    assert captured.value.status_code == 403
    assert captured.value.details == {}
    return captured.value


@pytest.mark.parametrize("role_id", CANONICAL_ROLES)
def test_verified_active_membership_builds_exact_human_authorization_snapshot(
    role_id: str,
) -> None:
    context = _resolve(claims=_claims(role_id=role_id))

    assert context.principal_type == "user"
    assert context.customer_id == CUSTOMER_ID
    assert context.deployment_id == DEPLOYMENT_ID
    assert context.granted_actions == frozenset()

    authorization = context.human_authorization
    assert authorization is not None
    assert authorization.authorization_path == "membership"
    assert authorization.schema_version == "human-authorization-context.v1"
    assert authorization.authorization_source == "pre_token_membership_v1"
    assert authorization.membership_state == "active"
    assert authorization.role_id == role_id
    assert authorization.membership_version == "7"
    assert authorization.authz_schema_version == AUTHZ_SCHEMA_VERSION
    assert authorization.scope_catalog_version == SCOPE_CATALOG_VERSION
    assert authorization.role_catalog_version == ROLE_CATALOG_VERSION
    assert authorization.policy_version == POLICY_VERSION
    assert authorization.policy_digest == POLICY_DIGEST
    assert authorization.issued_at == NOW - 30
    assert authorization.authenticated_at == NOW - 60
    assert authorization.assurance is None
    assert authorization.assurance_source is None
    assert authorization.assurance_version is None
    assert authorization.authentication_event_reference is None


def test_raw_assurance_claims_never_create_phishing_resistant_authority() -> None:
    without_assurance = _claims()
    without_assurance.pop(ASSURANCE_CLAIM)
    without_assurance["assurance"] = PHISHING_RESISTANT_MFA
    without_assurance["custom:amr"] = PHISHING_RESISTANT_MFA

    context = _resolve(claims=without_assurance)

    assert context.human_authorization is not None
    assert context.human_authorization.assurance is None


@pytest.mark.parametrize(
    "value",
    ["", "   ", "password_mfa", "unknown", 7, True, [PHISHING_RESISTANT_MFA]],
)
def test_unreviewed_assurance_claim_values_are_ignored(value: object) -> None:
    context = _resolve(claims=_claims(**{ASSURANCE_CLAIM: value}))

    assert context.human_authorization is not None
    assert context.human_authorization.assurance is None


def test_human_parser_accepts_access_tokens_only() -> None:
    with pytest.raises(AppError) as captured:
        _resolve(claims=_claims(token_use="id"))

    assert captured.value.status_code == 401
    assert captured.value.details == {}


@pytest.mark.parametrize("principal_type", [None, "", "m2m", "local_mock", "USER", 7])
def test_principal_type_must_be_exactly_user(principal_type: object) -> None:
    claims = _claims(principal_type=principal_type)
    if principal_type is None:
        claims.pop("principal_type")

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    "subject",
    [
        None,
        "",
        "   ",
        "synthetic subject",
        "synthetic\nsubject",
        "synthétic-subject",
        "a" * 257,
        7,
        ["synthetic-subject"],
    ],
)
def test_human_subject_must_match_canonical_schema(subject: object) -> None:
    claims = _claims(sub=subject)
    if subject is None:
        claims.pop("sub")

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    ("claim_name", "claim_value"),
    [
        ("custom:customerId", FOREIGN_CUSTOMER_ID),
        ("custom:customerId", "legacy-customer"),
        ("custom:deployment_id", FOREIGN_DEPLOYMENT_ID),
        ("custom:deployment_id", "legacy-deployment"),
    ],
)
def test_signed_customer_and_deployment_must_exactly_match_runtime_binding(
    claim_name: str,
    claim_value: str,
) -> None:
    _assert_forbidden(lambda: _resolve(claims=_claims(**{claim_name: claim_value})))


@pytest.mark.parametrize("claim_name", ["custom:customerId", "custom:deployment_id"])
def test_missing_canonical_customer_or_deployment_claim_fails_closed(
    claim_name: str,
) -> None:
    claims = _claims()
    claims.pop(claim_name)

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    ("legacy_claim", "foreign_value"),
    [
        ("tenant_id", FOREIGN_CUSTOMER_ID),
        ("tenantId", FOREIGN_CUSTOMER_ID),
        ("custom:tenantId", FOREIGN_CUSTOMER_ID),
        ("customer_id", FOREIGN_CUSTOMER_ID),
        ("customerId", FOREIGN_CUSTOMER_ID),
        ("custom:customer_id", FOREIGN_CUSTOMER_ID),
        ("deployment_id", FOREIGN_DEPLOYMENT_ID),
        ("deploymentId", FOREIGN_DEPLOYMENT_ID),
        ("custom:deploymentId", FOREIGN_DEPLOYMENT_ID),
    ],
)
def test_conflicting_legacy_identity_claims_fail_closed(
    legacy_claim: str,
    foreign_value: str,
) -> None:
    _assert_forbidden(
        lambda: _resolve(claims=_claims(**{legacy_claim: foreign_value}))
    )


@pytest.mark.parametrize(
    ("alternative_claim", "canonical_value"),
    [
        ("tenant_id", CUSTOMER_ID),
        ("tenantId", CUSTOMER_ID),
        ("custom:tenantId", CUSTOMER_ID),
        ("customer_id", CUSTOMER_ID),
        ("customerId", CUSTOMER_ID),
        ("custom:customer_id", CUSTOMER_ID),
        ("deployment_id", DEPLOYMENT_ID),
        ("deploymentId", DEPLOYMENT_ID),
        ("custom:deploymentId", DEPLOYMENT_ID),
    ],
)
def test_matching_alternative_identity_claims_fail_closed(
    alternative_claim: str,
    canonical_value: str,
) -> None:
    _assert_forbidden(
        lambda: _resolve(claims=_claims(**{alternative_claim: canonical_value}))
    )


@pytest.mark.parametrize(
    ("canonical_claim", "legacy_claim", "legacy_value"),
    [
        ("custom:customerId", "tenantId", CUSTOMER_ID),
        ("custom:deployment_id", "deploymentId", DEPLOYMENT_ID),
    ],
)
def test_legacy_only_identity_claims_never_become_authority(
    canonical_claim: str,
    legacy_claim: str,
    legacy_value: str,
) -> None:
    claims = _claims(**{legacy_claim: legacy_value})
    claims.pop(canonical_claim)

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    "membership_state",
    [None, "", "invited", "suspended", "revoked", "expired", "ACTIVE", 7],
)
def test_only_exact_active_membership_state_authorizes(
    membership_state: object,
) -> None:
    claims = _claims(membership_state=membership_state)
    if membership_state is None:
        claims.pop("membership_state")

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    "role_id",
    [None, "", "   ", "platform_admin", "custom_role", "CUSTOMER_ADMIN", 7],
)
def test_unknown_missing_or_malformed_human_role_fails_closed(role_id: object) -> None:
    claims = _claims(role_id=role_id)
    if role_id is None:
        claims.pop("role_id")

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    "membership_version",
    [None, "", "   ", "version with spaces", "version/7", "é", "v" * 129, 0, 7, True, []],
)
def test_membership_version_must_match_canonical_schema(
    membership_version: object,
) -> None:
    claims = _claims(membership_version=membership_version)
    if membership_version is None:
        claims.pop("membership_version")

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    ("claim_name", "invalid_value"),
    [
        ("authz_schema_version", None),
        ("authz_schema_version", "enterprise-authorization.v2"),
        ("scope_catalog_version", None),
        ("scope_catalog_version", "scanalyze.api.v2"),
        ("role_catalog_version", None),
        ("role_catalog_version", "enterprise-roles.v2"),
        ("policy_version", None),
        ("policy_version", "2.0.0"),
        ("policy_digest", None),
        ("policy_digest", OTHER_POLICY_DIGEST),
        ("policy_digest", "malformed"),
    ],
)
def test_missing_conflicting_or_future_contract_version_fails_closed(
    claim_name: str,
    invalid_value: object,
) -> None:
    claims = _claims(**{claim_name: invalid_value})
    if invalid_value is None:
        claims.pop(claim_name)

    _assert_forbidden(lambda: _resolve(claims=claims))


@pytest.mark.parametrize(
    ("claim_name", "invalid_value"),
    [
        ("iat", None),
        ("iat", "1800000000"),
        ("iat", True),
        ("iat", 0),
        ("iat", NOW + 1),
        ("iat", NOW - SNAPSHOT_MAX_AGE_SECONDS - 1),
        ("auth_time", None),
        ("auth_time", "1799999940"),
        ("auth_time", True),
        ("auth_time", 0),
        ("auth_time", NOW + 1),
        ("auth_time", NOW - 10),
    ],
)
def test_invalid_token_or_membership_snapshot_times_fail_closed(
    claim_name: str,
    invalid_value: object,
) -> None:
    claims = _claims(**{claim_name: invalid_value})
    if invalid_value is None:
        claims.pop(claim_name)
    if claim_name == "auth_time" and invalid_value == NOW - 10:
        claims["iat"] = NOW - 30  # Authentication cannot occur after token issue.

    _assert_forbidden(lambda: _resolve(claims=claims))


def test_membership_snapshot_at_exact_freshness_boundary_is_accepted() -> None:
    context = _resolve(
        claims=_claims(iat=NOW - SNAPSHOT_MAX_AGE_SECONDS, auth_time=NOW - 3600)
    )

    assert context.human_authorization is not None
    assert context.human_authorization.issued_at == NOW - SNAPSHOT_MAX_AGE_SECONDS
    assert context.human_authorization.authenticated_at == NOW - 3600


@pytest.mark.parametrize(
    "setting_name",
    [
        "enterprise_authorization_schema_version",
        "enterprise_scope_catalog_version",
        "enterprise_role_catalog_version",
        "enterprise_policy_version",
        "enterprise_policy_digest",
        "enterprise_membership_snapshot_max_age_seconds",
    ],
)
def test_missing_runtime_authorization_contract_setting_fails_closed(
    setting_name: str,
) -> None:
    settings = _settings()
    delattr(settings, setting_name)

    _assert_forbidden(lambda: _resolve(settings=settings))


@pytest.mark.parametrize(
    ("setting_name", "invalid_value"),
    [
        ("enterprise_authorization_schema_version", "enterprise-authorization.v2"),
        ("enterprise_scope_catalog_version", "scanalyze.api.v2"),
        ("enterprise_role_catalog_version", "enterprise-roles.v2"),
        ("enterprise_policy_version", "2.0.0"),
        ("enterprise_policy_digest", OTHER_POLICY_DIGEST),
        ("enterprise_policy_digest", "malformed"),
    ],
)
def test_runtime_contract_configuration_must_match_verified_claims(
    setting_name: str,
    invalid_value: str,
) -> None:
    settings = _settings()
    setattr(settings, setting_name, invalid_value)

    _assert_forbidden(lambda: _resolve(settings=settings))


@pytest.mark.parametrize("max_age", [0, -1, True, "300", None])
def test_invalid_membership_snapshot_max_age_setting_fails_closed(
    max_age: object,
) -> None:
    _assert_forbidden(
        lambda: _resolve(
            settings=_settings(
                enterprise_membership_snapshot_max_age_seconds=max_age
            )
        )
    )


@pytest.mark.parametrize(
    "claim_name",
    [None, "", "   ", "sub", "auth_time", "custom:customerId", 7],
)
def test_legacy_assurance_claim_configuration_is_inert(
    claim_name: object,
) -> None:
    context = _resolve(
        settings=_settings(enterprise_assurance_claim_name=claim_name)
    )

    assert context.human_authorization is not None
    assert context.human_authorization.assurance is None


def test_assurance_claim_configuration_is_not_required() -> None:
    settings = _settings()
    delattr(settings, "enterprise_assurance_claim_name")

    context = _resolve(settings=settings)

    assert context.human_authorization is not None
    assert context.human_authorization.assurance is None


@pytest.mark.parametrize("legacy_header", [CUSTOMER_ID, FOREIGN_CUSTOMER_ID])
def test_legacy_identity_header_is_rejected_even_when_it_matches(
    legacy_header: str,
) -> None:
    _assert_forbidden(lambda: _resolve(legacy_tenant_header=legacy_header))


def test_request_payload_and_extra_token_scopes_never_create_human_authority() -> None:
    untrusted_payload = {
        "customer_id": FOREIGN_CUSTOMER_ID,
        "deployment_id": FOREIGN_DEPLOYMENT_ID,
        "role_id": "customer_admin",
        "membership_state": "active",
        "policy_digest": OTHER_POLICY_DIGEST,
    }
    assert "payload" not in inspect.signature(_resolve_cognito_auth).parameters

    context = _resolve(
        claims=_claims(
            role_id="document_operator",
            **{
                "cognito:groups": ["customer_admin"],
                "custom:role_id": "customer_admin",
            },
            scope=(
                "scanalyze.api.v1/read scanalyze.api.v1/write "
                "scanalyze.api.v1/admin synthetic/unreviewed"
            ),
        )
    )

    assert untrusted_payload["role_id"] == "customer_admin"
    assert context.customer_id == CUSTOMER_ID
    assert context.deployment_id == DEPLOYMENT_ID
    assert context.granted_actions == frozenset()
    assert context.human_authorization is not None
    assert context.human_authorization.role_id == "document_operator"


def test_m2m_context_has_no_human_authorization_snapshot() -> None:
    context = AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="m2m",
        subject="synthetic-machine-subject",
        client_id="synthetic-machine-client",
        granted_actions=("read",),
        auth_source="m2m_identity_binding_v1",
    )

    assert context.human_authorization is None
