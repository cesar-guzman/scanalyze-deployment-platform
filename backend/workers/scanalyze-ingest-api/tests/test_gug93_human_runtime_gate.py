"""Fail-closed GUG-93 handoff tests for the disabled human runtime."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.auth import _resolve_cognito_auth
from app.config import validate_auth_config
from app.errors import AppError


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _settings(*, human_enabled: bool, env: str = "staging") -> SimpleNamespace:
    return SimpleNamespace(
        env=env,
        auth_mode="cognito_jwt",
        cognito_user_pool_id="us-east-1_SYNTHETIC",
        cognito_region="us-east-1",
        cognito_allowed_token_uses="access",
        cognito_allowed_client_ids="synthetic-spa-client",
        tenant_claim_name="custom:customerId",
        deployment_claim_name="custom:deployment_id",
        scanalyze_deployment_customer_id=CUSTOMER_ID,
        scanalyze_deployment_id=DEPLOYMENT_ID,
        m2m_tenant_resolution="disabled",
        m2m_client_tenant_map=None,
        m2m_client_identity_bindings_v1=None,
        m2m_action_scope_sets_v1=None,
        human_enterprise_authorization_enabled=human_enabled,
    )


def test_customer_deployment_cannot_enable_unproven_human_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENFORCE_AUTH_HEADER", raising=False)
    monkeypatch.delenv("TENANT_HEADER_NAME", raising=False)

    with pytest.raises(RuntimeError, match="must remain false"):
        validate_auth_config(_settings(human_enabled=True))


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
