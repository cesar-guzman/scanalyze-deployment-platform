"""Fail-closed GUG-93 handoff tests for the reviewed human runtime contract."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.auth import _resolve_cognito_auth
from app.config import validate_auth_config
from app.enterprise_authorization import (
    AUTHZ_SCHEMA_VERSION,
    MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
)
from app.errors import AppError


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
ASSURANCE_CLAIM = "custom:authentication_assurance"


def _settings(
    *,
    human_enabled: bool,
    env: str = "staging",
    **overrides: object,
) -> SimpleNamespace:
    values = {
        "env": env,
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
        "human_enterprise_authorization_enabled": human_enabled,
        "enterprise_authorization_schema_version": AUTHZ_SCHEMA_VERSION,
        "enterprise_scope_catalog_version": SCOPE_CATALOG_VERSION,
        "enterprise_role_catalog_version": ROLE_CATALOG_VERSION,
        "enterprise_policy_version": POLICY_VERSION,
        "enterprise_policy_digest": POLICY_DIGEST,
        "enterprise_membership_snapshot_max_age_seconds": (
            MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS
        ),
        "enterprise_assurance_claim_name": ASSURANCE_CLAIM,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_customer_deployment_can_enable_exact_reviewed_human_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)

    validate_auth_config(_settings(human_enabled=True))


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "error_fragment"),
    [
        (
            "enterprise_authorization_schema_version",
            None,
            "ENTERPRISE_AUTHORIZATION_SCHEMA_VERSION",
        ),
        (
            "enterprise_scope_catalog_version",
            "stale-scope-catalog",
            "ENTERPRISE_SCOPE_CATALOG_VERSION",
        ),
        (
            "enterprise_role_catalog_version",
            "unknown-role-catalog",
            "ENTERPRISE_ROLE_CATALOG_VERSION",
        ),
        (
            "enterprise_policy_version",
            "0.0.0",
            "ENTERPRISE_POLICY_VERSION",
        ),
        (
            "enterprise_policy_digest",
            f"sha256:{'0' * 64}",
            "ENTERPRISE_POLICY_DIGEST",
        ),
        (
            "enterprise_membership_snapshot_max_age_seconds",
            MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS + 1,
            "ENTERPRISE_MEMBERSHIP_SNAPSHOT_MAX_AGE_SECONDS",
        ),
        (
            "enterprise_assurance_claim_name",
            "custom:customerId",
            "ENTERPRISE_ASSURANCE_CLAIM_NAME",
        ),
    ],
)
def test_customer_deployment_rejects_incomplete_or_conflicting_human_contract(
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    invalid_value: object,
    error_fragment: str,
) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)

    with pytest.raises(RuntimeError, match=error_fragment):
        validate_auth_config(
            _settings(
                human_enabled=True,
                **{field_name: invalid_value},
            )
        )


@pytest.mark.parametrize("env", ["local", "test", "ci", "staging"])
def test_verified_human_token_is_denied_before_tenant_resolution(env: str) -> None:
    claims = {
        "sub": "synthetic-subject",
        "username": "synthetic-user",
        "client_id": "synthetic-spa-client",
        "token_use": "access",
        "scope": "scanalyze.api.v1/read",
        "custom:customerId": CUSTOMER_ID,
        "custom:deployment_id": DEPLOYMENT_ID,
    }

    with patch("app.auth._verify_cognito_jwt", return_value=claims):
        with pytest.raises(AppError) as denied:
            _resolve_cognito_auth(
                token="synthetic-not-a-token",
                settings=_settings(human_enabled=False, env=env),
                legacy_tenant_header=None,
                request_path="/api/v1/documents",
            )

    assert denied.value.status_code == 403
    assert denied.value.message == "Access is not available for this principal"
    assert denied.value.details == {}


@pytest.mark.parametrize("gate_state", [None, "missing"])
def test_missing_or_ambiguous_human_gate_denies(gate_state: object) -> None:
    settings = _settings(human_enabled=False)
    if gate_state == "missing":
        del settings.human_enterprise_authorization_enabled
    else:
        settings.human_enterprise_authorization_enabled = gate_state
    claims = {
        "sub": "synthetic-subject",
        "username": "synthetic-user",
        "client_id": "synthetic-spa-client",
        "token_use": "access",
        "scope": "scanalyze.api.v1/read",
        "custom:customerId": CUSTOMER_ID,
        "custom:deployment_id": DEPLOYMENT_ID,
    }

    with patch("app.auth._verify_cognito_jwt", return_value=claims):
        with pytest.raises(AppError) as denied:
            _resolve_cognito_auth(
                token="synthetic-not-a-token",
                settings=settings,
                legacy_tenant_header=None,
                request_path="/api/v1/documents",
            )

    assert denied.value.status_code == 403
    assert denied.value.message == "Access is not available for this principal"
