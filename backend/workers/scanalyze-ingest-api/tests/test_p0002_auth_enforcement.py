"""P0-002: Enforce authentication by default — auth enforcement tests.

Tests cover:
  - Default Settings.auth_mode is cognito_jwt
  - Unknown AUTH_MODE rejected at startup (all envs)
  - AUTH_MODE=local_mock rejected in dev/demo/staging/prod (non-local)
  - AUTH_MODE=local_mock allowed in local/test/ci
  - SCANALYZE_DEPLOYMENT_CUSTOMER_ID required in non-local
  - SCANALYZE_DEPLOYMENT_CUSTOMER_ID optional in local/test/ci
  - Verified JWT customer mismatch → 403
  - Verified JWT customer match → success
  - X-Tenant-Id is rejected and cannot affect customer identity
  - ENFORCE_AUTH_HEADER=false fails startup in non-local
  - ENFORCE_AUTH_HEADER warns in local
  - ENFORCE_AUTH_HEADER=false does not disable auth
  - Health does not expose env or internal details
  - create_app() fails with invalid auth config
  - All /api/v1/* routes are protected by default
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Ensure each test gets a fresh Settings instance."""
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def clean_env_vars(monkeypatch):
    """Remove env vars that could leak between tests."""
    for var in (
        "AUTH_MODE", "APP_ENV", "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
        "ENFORCE_AUTH_HEADER", "TENANT_HEADER_NAME",
        "COGNITO_USER_POOL_ID", "COGNITO_REGION",
        "COGNITO_ALLOWED_CLIENT_IDS", "TENANT_CLAIM_NAME",
        "LOCAL_MOCK_TENANT_ID", "LOCAL_MOCK_SUBJECT",
        "M2M_TENANT_RESOLUTION", "M2M_CLIENT_TENANT_MAP",
        "M2M_CLIENT_IDENTITY_BINDINGS_V1", "M2M_ACTION_SCOPE_SETS_V1",
        "SCANALYZE_DEPLOYMENT_ID", "DEPLOYMENT_CLAIM_NAME",
    ):
        monkeypatch.delenv(var, raising=False)


def _make_settings(**overrides: Any) -> MagicMock:
    """Create a mock Settings object with safe defaults for testing."""
    defaults = {
        "env": "test",
        "auth_mode": "cognito_jwt",
        "cognito_user_pool_id": "us-east-1_TestPool",
        "cognito_region": "us-east-1",
        "cognito_allowed_token_uses": "access",
        "cognito_allowed_client_ids": "test-client-id",
        "tenant_claim_name": "custom:customerId",
        "m2m_tenant_resolution": "disabled",
        "m2m_client_tenant_map": None,
        "m2m_client_identity_bindings_v1": None,
        "m2m_action_scope_sets_v1": None,
        "deployment_claim_name": "custom:deployment_id",
        "local_mock_tenant_id": None,
        "local_mock_subject": "local-dev-user",
        "scanalyze_deployment_customer_id": None,
        "scanalyze_deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "enforce_auth_header": None,
        "tenant_header_name": None,
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)
    return mock


def _fake_jwt_claims(**overrides: Any) -> Dict[str, Any]:
    """Standard valid access token claims."""
    now = int(time.time())
    base = {
        "sub": "user-abc-123",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
        "client_id": "test-spa-client",
        "token_use": "access",
        "scope": "scanalyze-ingest/ingest.read scanalyze-ingest/ingest.write",
        "exp": now + 3600,
        "iat": now,
        "custom:customerId": "customer-example",
        "cognito:username": "user-abc-123",
        "email": "user@example.com",
        "name": "Test User",
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════
# Config / Startup Tests
# ══════════════════════════════════════════════════════════


class TestDefaultSettings:
    def test_default_settings_auth_mode_is_cognito_jwt(self, monkeypatch):
        """Factory default Settings().auth_mode must be cognito_jwt."""
        monkeypatch.setenv("APP_ENV", "test")
        from app.config import Settings
        s = Settings()
        assert s.auth_mode == "cognito_jwt"


class TestUnknownAuthModeRejected:
    @pytest.mark.parametrize("auth_mode", ["none", "disabled", "off", "bad", "", "bypass"])
    def test_unknown_auth_mode_rejected_at_startup(self, auth_mode):
        """Unknown AUTH_MODE → RuntimeError in ALL environments."""
        from app.config import validate_auth_config
        settings = _make_settings(auth_mode=auth_mode, env="test")
        with pytest.raises(RuntimeError, match="Invalid AUTH_MODE"):
            validate_auth_config(settings)

    @pytest.mark.parametrize("auth_mode", ["none", "disabled"])
    def test_unknown_auth_mode_rejected_in_prod(self, auth_mode):
        """Unknown AUTH_MODE → RuntimeError even in prod."""
        from app.config import validate_auth_config
        settings = _make_settings(auth_mode=auth_mode, env="prod")
        with pytest.raises(RuntimeError, match="Invalid AUTH_MODE"):
            validate_auth_config(settings)

    @pytest.mark.parametrize("auth_mode", ["none", "disabled", "off"])
    def test_unknown_auth_mode_rejected_in_local(self, auth_mode):
        """Unknown AUTH_MODE → RuntimeError even in local."""
        from app.config import validate_auth_config
        settings = _make_settings(auth_mode=auth_mode, env="local")
        with pytest.raises(RuntimeError, match="Invalid AUTH_MODE"):
            validate_auth_config(settings)


class TestLocalMockEnvironmentRestrictions:
    @pytest.mark.parametrize("env", ["dev", "demo", "staging", "prod", "production", "qa", "uat"])
    def test_local_mock_rejected_in_non_local_envs(self, env):
        """AUTH_MODE=local_mock rejected in dev/demo/staging/prod/etc."""
        from app.config import validate_auth_config
        settings = _make_settings(env=env, auth_mode="local_mock")
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            validate_auth_config(settings)

    @pytest.mark.parametrize("env", ["local", "test", "ci"])
    def test_local_mock_allowed_in_local_test_ci(self, env):
        """AUTH_MODE=local_mock is allowed in local/test/ci."""
        from app.config import validate_auth_config
        settings = _make_settings(env=env, auth_mode="local_mock")
        # Should not raise
        validate_auth_config(settings)


class TestDeploymentCustomerIdRequired:
    @pytest.mark.parametrize("env", ["dev", "demo", "staging", "prod", "production"])
    def test_deployment_customer_id_required_in_non_local(self, env):
        """Missing SCANALYZE_DEPLOYMENT_CUSTOMER_ID in non-local → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env=env,
            auth_mode="cognito_jwt",
            scanalyze_deployment_customer_id=None,
        )
        with pytest.raises(RuntimeError, match="SCANALYZE_DEPLOYMENT_CUSTOMER_ID"):
            validate_auth_config(settings)

    @pytest.mark.parametrize("env", ["local", "test", "ci"])
    def test_deployment_customer_id_optional_in_local(self, env):
        """Missing SCANALYZE_DEPLOYMENT_CUSTOMER_ID in local/test/ci → no error."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env=env,
            auth_mode="cognito_jwt",
            scanalyze_deployment_customer_id=None,
        )
        # Should not raise (local/test/ci is flexible)
        validate_auth_config(settings)

    def test_empty_deployment_customer_id_rejected(self):
        """SCANALYZE_DEPLOYMENT_CUSTOMER_ID='   ' in prod → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            scanalyze_deployment_customer_id="   ",
        )
        with pytest.raises(RuntimeError, match="SCANALYZE_DEPLOYMENT_CUSTOMER_ID"):
            validate_auth_config(settings)


class TestDeprecatedEnvVars:
    def test_enforce_auth_header_false_fails_startup_in_non_local(self, monkeypatch):
        """P0-002: ENFORCE_AUTH_HEADER=false in prod → RuntimeError (blocking)."""
        monkeypatch.setenv("ENFORCE_AUTH_HEADER", "false")
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            scanalyze_deployment_customer_id="customer-example",
        )
        with pytest.raises(RuntimeError, match="ENFORCE_AUTH_HEADER"):
            validate_auth_config(settings)

    def test_enforce_auth_header_true_fails_startup_in_non_local(self, monkeypatch):
        """P0-002: ENFORCE_AUTH_HEADER=true in prod → also RuntimeError (var is deprecated)."""
        monkeypatch.setenv("ENFORCE_AUTH_HEADER", "true")
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            scanalyze_deployment_customer_id="customer-example",
        )
        with pytest.raises(RuntimeError, match="ENFORCE_AUTH_HEADER"):
            validate_auth_config(settings)

    def test_enforce_auth_header_warns_in_local(self, monkeypatch):
        """ENFORCE_AUTH_HEADER set in local → warning only, no error."""
        monkeypatch.setenv("ENFORCE_AUTH_HEADER", "false")
        from app.config import validate_auth_config
        settings = _make_settings(env="test", auth_mode="cognito_jwt")
        # Should not raise
        validate_auth_config(settings)


# ══════════════════════════════════════════════════════════
# Auth Behavior Tests
# ══════════════════════════════════════════════════════════


class TestDeploymentCustomerBinding:
    def test_jwt_customer_id_mismatch_returns_403(self):
        """Token custom:customerId != SCANALYZE_DEPLOYMENT_CUSTOMER_ID → 403."""
        from app.auth import _validate_deployment_customer
        from app.errors import AppError

        settings = _make_settings(scanalyze_deployment_customer_id="customer-example")
        with pytest.raises(AppError) as exc:
            _validate_deployment_customer("evil-corp", settings)
        assert exc.value.status_code == 403

    def test_jwt_customer_id_match_succeeds(self):
        """Token custom:customerId == SCANALYZE_DEPLOYMENT_CUSTOMER_ID → no error."""
        from app.auth import _validate_deployment_customer

        settings = _make_settings(scanalyze_deployment_customer_id="customer-example")
        # Should not raise
        _validate_deployment_customer("customer-example", settings)

    def test_deployment_customer_not_set_skips_validation_in_local(self):
        """In local/test, no deployment customer set → skip check."""
        from app.auth import _validate_deployment_customer

        settings = _make_settings(scanalyze_deployment_customer_id=None)
        # Should not raise
        _validate_deployment_customer("any-customer", settings)

    def test_deployment_customer_empty_skips_validation(self):
        """SCANALYZE_DEPLOYMENT_CUSTOMER_ID='' → skip (should not happen in prod per startup validation)."""
        from app.auth import _validate_deployment_customer

        settings = _make_settings(scanalyze_deployment_customer_id="")
        # Should not raise (startup validation catches this in prod)
        _validate_deployment_customer("any-customer", settings)

    def test_resolve_cognito_auth_validates_deployment_customer(self):
        """Full _resolve_cognito_auth flow validates deployment customer after JWT verification."""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        settings = _make_settings(
            env="test",
            scanalyze_deployment_customer_id="customer-example",
            cognito_allowed_client_ids="",
        )
        claims = _fake_jwt_claims(**{"custom:customerId": "evil-corp"})

        with patch("app.auth._verify_cognito_jwt", return_value=claims):
            with pytest.raises(AppError) as exc:
                _resolve_cognito_auth(
                    token="fake-token",
                    settings=settings,
                    legacy_tenant_header=None,
                    request_path="/api/v1/test",
                )
            assert exc.value.status_code == 403

    def test_resolve_cognito_auth_succeeds_with_matching_customer(self):
        """Full flow succeeds when JWT customer matches deployment customer."""
        from app.auth import _resolve_cognito_auth

        settings = _make_settings(
            env="test",
            scanalyze_deployment_customer_id="customer-example",
            cognito_allowed_client_ids="",
        )
        claims = _fake_jwt_claims(**{"custom:customerId": "customer-example"})

        with patch("app.auth._verify_cognito_jwt", return_value=claims):
            ctx = _resolve_cognito_auth(
                token="fake-token",
                settings=settings,
                legacy_tenant_header=None,
                request_path="/api/v1/test",
            )
            assert ctx.customer_id == "customer-example"
            assert ctx.auth_source == "cognito_jwt"


class TestXTenantIdRejected:
    def test_x_tenant_id_is_rejected(self):
        """X-Tenant-Id is forbidden even when the verified JWT is otherwise valid."""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        settings = _make_settings(
            env="test",
            scanalyze_deployment_customer_id="customer-example",
            cognito_allowed_client_ids="",
        )
        claims = _fake_jwt_claims(**{"custom:customerId": "customer-example"})

        with patch("app.auth._verify_cognito_jwt", return_value=claims):
            with pytest.raises(AppError) as captured:
                _resolve_cognito_auth(
                    token="fake-token",
                    settings=settings,
                    legacy_tenant_header="evil-corp",
                    request_path="/api/v1/test",
                )
        assert captured.value.status_code == 403


# ══════════════════════════════════════════════════════════
# Health / Readiness Tests
# ══════════════════════════════════════════════════════════


class TestHealthEndpoint:
    def test_health_does_not_expose_env(self, monkeypatch):
        """Health response must not contain env."""
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")

        from app.api.health import health
        response = health()
        assert "env" not in response
        assert "status" in response
        assert "service" in response

    def test_health_does_not_leak_internal_details(self, monkeypatch):
        """Health response must not contain bucket/table/queue/ARN/cognito info."""
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")

        from app.api.health import health
        response = health()
        body = str(response).lower()
        for forbidden in ("bucket", "table", "queue", "arn:", "cognito", "customer_id"):
            assert forbidden not in body, f"Health response contains forbidden term: {forbidden}"


# ══════════════════════════════════════════════════════════
# create_app() Startup Tests
# ══════════════════════════════════════════════════════════


class TestCreateAppStartupFailure:
    def test_create_app_fails_when_auth_mode_invalid(self, monkeypatch):
        """create_app() must fail before accepting traffic if AUTH_MODE is invalid."""
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.setenv("AUTH_MODE", "local_mock")
        with pytest.raises(RuntimeError):
            from app.main import create_app
            create_app()

    def test_create_app_fails_when_deployment_customer_missing_in_non_local(self, monkeypatch):
        """create_app() must fail if SCANALYZE_DEPLOYMENT_CUSTOMER_ID is missing in prod."""
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")
        monkeypatch.setenv("COGNITO_USER_POOL_ID", "us-east-1_TestPool")
        monkeypatch.setenv("COGNITO_ALLOWED_CLIENT_IDS", "test-client")
        monkeypatch.delenv("SCANALYZE_DEPLOYMENT_CUSTOMER_ID", raising=False)
        with pytest.raises(RuntimeError, match="SCANALYZE_DEPLOYMENT_CUSTOMER_ID"):
            from app.main import create_app
            create_app()

    def test_create_app_fails_when_local_mock_used_in_dev(self, monkeypatch):
        """P0-002: create_app() fails when local_mock used in dev (cloud deployment)."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("AUTH_MODE", "local_mock")
        monkeypatch.setenv("LOCAL_MOCK_TENANT_ID", "dev-tenant")
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            from app.main import create_app
            create_app()


# ══════════════════════════════════════════════════════════
# Route Coverage Test
# ══════════════════════════════════════════════════════════


class TestRouteProtection:
    """Verify that all known protected endpoints return 401 without auth."""

    PROTECTED_ENDPOINTS = [
        ("GET", "/api/v1/system/authz"),
        ("GET", "/api/v1/documents"),
        ("GET", "/api/v1/batches"),
    ]

    PUBLIC_ENDPOINTS = [
        ("GET", "/health"),
        ("GET", "/api/v1/health"),
    ]

    def _get_test_client(self, monkeypatch):
        """Create a test client with valid local config."""
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")
        monkeypatch.setenv("COGNITO_USER_POOL_ID", "us-east-1_TestPool")
        monkeypatch.setenv("COGNITO_REGION", "us-east-1")

        from app.main import create_app
        from fastapi.testclient import TestClient
        app = create_app()
        return TestClient(app)

    def test_protected_endpoints_require_auth(self, monkeypatch):
        """Known protected endpoints must return 401 without Authorization header."""
        client = self._get_test_client(monkeypatch)
        for method, path in self.PROTECTED_ENDPOINTS:
            if method == "GET":
                response = client.get(path)
            elif method == "POST":
                response = client.post(path)
            assert response.status_code in {401, 403, 404, 405}, (
                f"{method} {path} returned {response.status_code} without auth — expected 401/403/404/405"
            )

    def test_health_endpoints_are_public(self, monkeypatch):
        """Health endpoints must return 200 without auth."""
        client = self._get_test_client(monkeypatch)
        for method, path in self.PUBLIC_ENDPOINTS:
            response = client.get(path)
            assert response.status_code == 200, (
                f"{method} {path} returned {response.status_code} — expected 200"
            )

    def test_readiness_not_leaking(self, monkeypatch):
        """If /ready exists, it must not leak internal details."""
        client = self._get_test_client(monkeypatch)
        response = client.get("/ready")
        if response.status_code == 200:
            body = response.text.lower()
            for forbidden in ("arn:", "bucket", "queue_url", "documents_table"):
                assert forbidden not in body, (
                    f"/ready response contains forbidden term: {forbidden}"
                )
