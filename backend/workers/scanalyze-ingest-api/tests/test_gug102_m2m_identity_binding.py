"""GUG-102 WP1 regression contract for fail-closed M2M identity binding.

These tests intentionally describe the target runtime contract before the
implementation changes.  All identities and scopes are synthetic.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.api.v1.models import CreateDocumentRequest
from app.auth import _resolve_cognito_auth, get_auth_context
from app.config import M2MClientIdentityBindingV1, Settings, validate_auth_config
from app.enterprise_authorization import (
    AUTHZ_SCHEMA_VERSION,
    MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
)
from app.errors import AppError


CLIENT_ID = "synthetic-m2m-client"
OTHER_CLIENT_ID = "synthetic-unmapped-client"
CUSTOMER_A = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
CUSTOMER_B = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
DEPLOYMENT_A = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_B = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAY"
READ_SCOPE = "https://api.synthetic.invalid/read"
WRITE_SCOPE = "https://api.synthetic.invalid/write"
ADMIN_SCOPE = "https://api.synthetic.invalid/admin"
ASSURANCE_CLAIM = "custom:authentication_assurance"


def _binding(
    *,
    customer_id: str = CUSTOMER_A,
    deployment_id: str = DEPLOYMENT_A,
    required_scopes: tuple[str, ...] = (READ_SCOPE, WRITE_SCOPE),
) -> dict[str, Any]:
    return {
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "required_scopes": list(required_scopes),
    }


def _settings(
    *,
    expected_customer_id: str = CUSTOMER_A,
    expected_deployment_id: str = DEPLOYMENT_A,
    bindings: dict[str, dict[str, Any]] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        env="test",
        auth_mode="cognito_jwt",
        tenant_claim_name="custom:customerId",
        deployment_claim_name="custom:deployment_id",
        cognito_user_pool_id="us-east-1_SyntheticPool",
        cognito_region="us-east-1",
        cognito_allowed_token_uses="access",
        cognito_allowed_client_ids=CLIENT_ID,
        scanalyze_deployment_customer_id=expected_customer_id,
        scanalyze_deployment_id=expected_deployment_id,
        m2m_tenant_resolution="client_identity_bindings_v1",
        m2m_client_identity_bindings_v1=(
            {CLIENT_ID: _binding()} if bindings is None else bindings
        ),
        m2m_action_scope_sets_v1={
            "read": [READ_SCOPE],
            "write": [WRITE_SCOPE],
            "admin": [ADMIN_SCOPE],
        },
        human_enterprise_authorization_enabled=False,
        enterprise_authorization_schema_version=AUTHZ_SCHEMA_VERSION,
        enterprise_scope_catalog_version=SCOPE_CATALOG_VERSION,
        enterprise_role_catalog_version=ROLE_CATALOG_VERSION,
        enterprise_policy_version=POLICY_VERSION,
        enterprise_policy_digest=POLICY_DIGEST,
        enterprise_membership_snapshot_max_age_seconds=(
            MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS
        ),
        enterprise_assurance_claim_name=ASSURANCE_CLAIM,
        # Legacy customer-only mappings must never authorize the new contract.
        m2m_client_tenant_map=None,
        enforce_auth_header=None,
        tenant_header_name=None,
    )


def _claims(
    *,
    client_id: str = CLIENT_ID,
    customer_id: str = CUSTOMER_A,
    deployment_id: str = DEPLOYMENT_A,
    token_use: str = "access",
    scopes: tuple[str, ...] = (READ_SCOPE, WRITE_SCOPE),
) -> dict[str, Any]:
    return {
        "sub": "synthetic-service-principal",
        "client_id": client_id,
        "token_use": token_use,
        "scope": " ".join(scopes),
        "custom:customerId": customer_id,
        "custom:deployment_id": deployment_id,
        # Deliberately no cognito:username: this is a machine principal.
    }


def _resolve(
    *,
    settings: SimpleNamespace | None = None,
    claims: dict[str, Any] | None = None,
    legacy_tenant_header: str | None = None,
):
    with patch("app.auth._verify_cognito_jwt", return_value=claims or _claims()):
        return _resolve_cognito_auth(
            token="synthetic-token-not-a-real-jwt",
            settings=settings or _settings(),
            legacy_tenant_header=legacy_tenant_header,
            request_path="/api/v1/documents",
        )


def _assert_forbidden(callable_under_test) -> None:
    with pytest.raises(AppError) as captured:
        callable_under_test()
    assert captured.value.status_code == 403


def test_valid_m2m_tuple_returns_fully_bound_typed_context() -> None:
    context = _resolve()

    assert context.customer_id == CUSTOMER_A
    assert context.deployment_id == DEPLOYMENT_A
    assert context.principal_type == "m2m"
    assert context.client_id == CLIENT_ID
    assert context.scopes == frozenset({READ_SCOPE, WRITE_SCOPE})
    assert context.granted_actions == frozenset({"read", "write"})
    # Existing handlers may use this read-only compatibility alias, but it must
    # never become an independent source of identity.
    assert context.tenant == CUSTOMER_A


def test_mapped_customer_must_match_runtime_customer() -> None:
    settings = _settings(expected_customer_id=CUSTOMER_B)
    claims = _claims(customer_id=CUSTOMER_B)

    _assert_forbidden(lambda: _resolve(settings=settings, claims=claims))


def test_mapped_deployment_must_match_runtime_deployment() -> None:
    settings = _settings(expected_deployment_id=DEPLOYMENT_B)
    claims = _claims(deployment_id=DEPLOYMENT_B)

    _assert_forbidden(lambda: _resolve(settings=settings, claims=claims))


def test_machine_principal_without_mapping_fails_closed() -> None:
    settings = _settings(bindings={})
    claims = _claims(client_id=OTHER_CLIENT_ID)

    _assert_forbidden(lambda: _resolve(settings=settings, claims=claims))


def test_machine_principal_with_customer_claim_cannot_bypass_disabled_mode() -> None:
    settings = _settings(bindings={})
    settings.m2m_tenant_resolution = "disabled"

    _assert_forbidden(lambda: _resolve(settings=settings, claims=_claims()))


@pytest.mark.parametrize("username_claim", ["cognito:username", "username"])
def test_binding_membership_does_not_reclassify_user_principal(
    username_claim: str,
) -> None:
    claims = _claims()
    now_epoch = int(time.time())
    claims.update(
        {
            username_claim: "synthetic-user",
            "principal_type": "user",
            "membership_state": "active",
            "role_id": "document_operator",
            "membership_version": "synthetic-membership-v1",
            "authz_schema_version": AUTHZ_SCHEMA_VERSION,
            "scope_catalog_version": SCOPE_CATALOG_VERSION,
            "role_catalog_version": ROLE_CATALOG_VERSION,
            "policy_version": POLICY_VERSION,
            "policy_digest": POLICY_DIGEST,
            "iat": now_epoch - 30,
            "auth_time": now_epoch - 60,
        }
    )
    settings = _settings()
    settings.human_enterprise_authorization_enabled = True

    context = _resolve(settings=settings, claims=claims)

    assert context.principal_type == "user"
    assert context.auth_source == "cognito_jwt"
    assert context.customer_id == CUSTOMER_A
    assert context.deployment_id == DEPLOYMENT_A
    assert context.human_authorization is not None
    assert context.human_authorization.membership_version == "synthetic-membership-v1"


@pytest.mark.parametrize(
    ("customer_id", "deployment_id"),
    [
        ("legacy-customer-slug", DEPLOYMENT_A),
        (CUSTOMER_A, "legacy-deployment-slug"),
        (DEPLOYMENT_A, DEPLOYMENT_A),
    ],
    ids=["malformed-customer", "malformed-deployment", "identical-identities"],
)
def test_malformed_or_identical_binding_is_rejected(
    customer_id: str,
    deployment_id: str,
) -> None:
    settings = _settings(
        expected_customer_id=customer_id,
        expected_deployment_id=deployment_id,
        bindings={
            CLIENT_ID: _binding(
                customer_id=customer_id,
                deployment_id=deployment_id,
            )
        },
    )
    claims = _claims(customer_id=customer_id, deployment_id=deployment_id)

    _assert_forbidden(lambda: _resolve(settings=settings, claims=claims))


def test_m2m_identity_binding_requires_access_token() -> None:
    with pytest.raises(AppError) as captured:
        _resolve(claims=_claims(token_use="id"))

    assert captured.value.status_code == 401


def test_m2m_identity_binding_requires_every_configured_scope() -> None:
    claims = _claims(scopes=(READ_SCOPE,))

    _assert_forbidden(lambda: _resolve(claims=claims))


def test_extra_token_scopes_do_not_elevate_binding_actions() -> None:
    settings = _settings(
        bindings={CLIENT_ID: _binding(required_scopes=(READ_SCOPE,))},
    )
    claims = _claims(scopes=(READ_SCOPE, WRITE_SCOPE, ADMIN_SCOPE, "synthetic-extra"))

    context = _resolve(settings=settings, claims=claims)

    assert context.scopes == frozenset(
        {READ_SCOPE, WRITE_SCOPE, ADMIN_SCOPE, "synthetic-extra"}
    )
    assert context.granted_actions == frozenset({"read"})


@pytest.mark.parametrize(
    ("claim_name", "claim_value"),
    [
        ("custom:customerId", CUSTOMER_B),
        ("custom:deployment_id", DEPLOYMENT_B),
    ],
    ids=["customer-claim", "deployment-claim"],
)
def test_signed_identity_claim_must_not_contradict_binding(
    claim_name: str,
    claim_value: str,
) -> None:
    claims = _claims()
    claims[claim_name] = claim_value

    _assert_forbidden(lambda: _resolve(claims=claims))


def test_identity_override_header_is_rejected() -> None:
    _assert_forbidden(
        lambda: _resolve(legacy_tenant_header=CUSTOMER_B),
    )


def test_identity_override_header_is_rejected_in_local_mock_mode() -> None:
    settings = SimpleNamespace(
        env="test",
        auth_mode="local_mock",
        local_mock_tenant_id="synthetic-local-customer",
        local_mock_subject="synthetic-local-user",
    )
    request = SimpleNamespace(url=SimpleNamespace(path="/api/v1/documents"))

    with patch("app.auth.get_settings", return_value=settings):
        with pytest.raises(AppError) as captured:
            get_auth_context(
                request=request,
                authorization=None,
                x_tenant_id=CUSTOMER_B,
            )

    assert captured.value.status_code == 403


@pytest.mark.parametrize(
    "untrusted_field",
    ["customer_id", "deployment_id", "tenantId", "Customer-ID"],
)
def test_identity_override_payload_is_rejected(untrusted_field: str) -> None:
    payload = {
        "contentType": "application/pdf",
        untrusted_field: CUSTOMER_B,
    }

    with pytest.raises(ValidationError):
        CreateDocumentRequest.model_validate(payload)


def test_unrelated_payload_extension_remains_compatible() -> None:
    request = CreateDocumentRequest.model_validate(
        {
            "contentType": "application/pdf",
            "synthetic_extension": "allowed-but-not-authoritative",
        }
    )

    assert request.contentType == "application/pdf"


def test_remote_m2m_mode_requires_versioned_binding_map(monkeypatch) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings(bindings={})
    settings.env = "prod"

    with pytest.raises(RuntimeError, match="M2M_CLIENT_IDENTITY_BINDINGS_V1"):
        validate_auth_config(settings)


@pytest.mark.parametrize(
    "action_scope_policy",
    [
        None,
        {
            "read": [READ_SCOPE],
            "write": [READ_SCOPE],
            "admin": [ADMIN_SCOPE],
        },
        {
            "read": [],
            "write": [WRITE_SCOPE],
            "admin": [ADMIN_SCOPE],
        },
    ],
    ids=["missing", "overlapping", "empty-action"],
)
def test_remote_runtime_rejects_missing_or_malformed_action_scope_policy(
    monkeypatch,
    action_scope_policy,
) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings()
    settings.env = "prod"
    settings.m2m_action_scope_sets_v1 = action_scope_policy

    with pytest.raises(RuntimeError, match="M2M_ACTION_SCOPE_SETS_V1"):
        validate_auth_config(settings)


def test_remote_runtime_rejects_partial_action_scope_set(monkeypatch) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings(
        bindings={CLIENT_ID: _binding(required_scopes=(READ_SCOPE,))},
    )
    settings.env = "prod"
    settings.m2m_action_scope_sets_v1 = {
        "read": [READ_SCOPE, "https://api.synthetic.invalid/read-secondary"],
        "write": [WRITE_SCOPE],
        "admin": [ADMIN_SCOPE],
    }

    with pytest.raises(RuntimeError, match="all or none"):
        validate_auth_config(settings)


def test_remote_runtime_requires_expected_deployment_id(monkeypatch) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings()
    settings.env = "prod"
    settings.scanalyze_deployment_id = None

    with pytest.raises(RuntimeError, match="SCANALYZE_DEPLOYMENT_ID"):
        validate_auth_config(settings)


@pytest.mark.parametrize(
    ("expected_customer_id", "expected_deployment_id", "error_fragment"),
    [
        (CUSTOMER_B, DEPLOYMENT_A, "customer_id"),
        (CUSTOMER_A, DEPLOYMENT_B, "deployment_id"),
    ],
    ids=["customer-mismatch", "deployment-mismatch"],
)
def test_remote_binding_must_match_expected_runtime_identity(
    monkeypatch,
    expected_customer_id: str,
    expected_deployment_id: str,
    error_fragment: str,
) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings(
        expected_customer_id=expected_customer_id,
        expected_deployment_id=expected_deployment_id,
    )
    settings.env = "prod"

    with pytest.raises(RuntimeError, match=error_fragment):
        validate_auth_config(settings)


def test_remote_binding_client_must_be_in_allowed_client_ids(monkeypatch) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings()
    settings.env = "prod"
    settings.cognito_allowed_client_ids = OTHER_CLIENT_ID

    with pytest.raises(RuntimeError, match="COGNITO_ALLOWED_CLIENT_IDS"):
        validate_auth_config(settings)


def test_remote_startup_rejects_legacy_customer_only_map(monkeypatch) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)
    settings = _settings()
    settings.env = "prod"
    settings.m2m_tenant_resolution = "disabled"
    settings.m2m_client_tenant_map = {CLIENT_ID: CUSTOMER_A}

    with pytest.raises(RuntimeError, match="M2M_CLIENT_TENANT_MAP"):
        validate_auth_config(settings)


def test_settings_parses_versioned_binding_from_json(monkeypatch) -> None:
    for name in (
        "M2M_CLIENT_IDENTITY_BINDINGS_V1",
        "M2M_CLIENT_TENANT_MAP",
        "M2M_ACTION_SCOPE_SETS_V1",
        "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
        "SCANALYZE_DEPLOYMENT_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = Settings(
        APP_ENV="test",
        M2M_TENANT_RESOLUTION="client_identity_bindings_v1",
        M2M_CLIENT_IDENTITY_BINDINGS_V1=json.dumps({CLIENT_ID: _binding()}),
        M2M_ACTION_SCOPE_SETS_V1=json.dumps(
            {
                "read": [READ_SCOPE],
                "write": [WRITE_SCOPE],
                "admin": [ADMIN_SCOPE],
            }
        ),
        SCANALYZE_DEPLOYMENT_CUSTOMER_ID=CUSTOMER_A,
        SCANALYZE_DEPLOYMENT_ID=DEPLOYMENT_A,
    )

    binding = settings.m2m_client_identity_bindings_v1[CLIENT_ID]
    assert isinstance(binding, M2MClientIdentityBindingV1)
    assert binding.customer_id == CUSTOMER_A
    assert binding.deployment_id == DEPLOYMENT_A
    assert binding.required_scopes == (READ_SCOPE, WRITE_SCOPE)
