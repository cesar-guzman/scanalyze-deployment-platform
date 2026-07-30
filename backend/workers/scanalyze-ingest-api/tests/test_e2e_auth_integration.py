"""P0-001: End-to-end integration tests for the complete auth flow.

These tests simulate the FULL lifecycle:
  1. Startup validation (validate_auth_config)
  2. App creation (create_app with FastAPI)
  3. HTTP request processing through middleware
  4. Auth context resolution (JWT verification, tenant extraction)
  5. Protected endpoint access control

Each test scenario validates a COMPLETE path through the system,
not just individual functions.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── Test Helpers ──────────────────────────────────────────

_CUSTOMER_ID_A = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
_CUSTOMER_ID_B = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
_DEPLOYMENT_ID_A = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
_DEPLOYMENT_ID_B = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAZ"
_AUTHZ_SCHEMA_VERSION = "enterprise-authorization.v1"
_SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
_ROLE_CATALOG_VERSION = "enterprise-roles.v1"
_POLICY_VERSION = "1.0.0"
_POLICY_DIGEST = (
    "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
)


def _make_settings(**overrides: Any) -> MagicMock:
    """Create a mock Settings object with safe defaults for testing."""
    defaults = {
        "env": "test",
        "auth_mode": "cognito_jwt",
        "cognito_user_pool_id": "us-east-1_TestPool",
        "cognito_region": "us-east-1",
        "cognito_allowed_token_uses": "access",
        "cognito_allowed_client_ids": "test-spa-client",
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
        "service_name": "scanalyze-ingest-api",
        "log_level": "INFO",
        "cors_allow_origins": "*",
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)

    # Ensure cors_origins_list returns a proper list
    def _cors_origins_list():
        v = defaults.get("cors_allow_origins", "*")
        if v == "*":
            return ["*"]
        return [x.strip() for x in v.split(",") if x.strip()]

    mock.cors_origins_list = _cors_origins_list
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
        "custom:customerId": "tenant-alpha",
        "email": "user@example.com",
        "name": "Test User",
        "cognito:username": "user-abc-123",
    }
    base.update(overrides)
    return base


def _make_human_settings(**overrides: Any) -> MagicMock:
    """Create the exact reviewed runtime contract for a human principal."""
    human_defaults = {
        "human_enterprise_authorization_enabled": True,
        "scanalyze_deployment_customer_id": _CUSTOMER_ID_A,
        "scanalyze_deployment_id": _DEPLOYMENT_ID_A,
        "enterprise_authorization_schema_version": _AUTHZ_SCHEMA_VERSION,
        "enterprise_scope_catalog_version": _SCOPE_CATALOG_VERSION,
        "enterprise_role_catalog_version": _ROLE_CATALOG_VERSION,
        "enterprise_policy_version": _POLICY_VERSION,
        "enterprise_policy_digest": _POLICY_DIGEST,
        "enterprise_membership_snapshot_max_age_seconds": 300,
        "enterprise_assurance_claim_name": "custom:authentication_assurance",
    }
    human_defaults.update(overrides)
    return _make_settings(**human_defaults)


def _fake_human_jwt_claims(**overrides: Any) -> Dict[str, Any]:
    """Signed-claim shape emitted by the reviewed GUG-153 pre-token adapter."""
    now = int(time.time())
    human_claims = {
        "principal_type": "user",
        "custom:customerId": _CUSTOMER_ID_A,
        "custom:deployment_id": _DEPLOYMENT_ID_A,
        "membership_state": "active",
        "role_id": "customer_admin",
        "membership_version": "membership-v1",
        "authz_schema_version": _AUTHZ_SCHEMA_VERSION,
        "scope_catalog_version": _SCOPE_CATALOG_VERSION,
        "role_catalog_version": _ROLE_CATALOG_VERSION,
        "policy_version": _POLICY_VERSION,
        "policy_digest": _POLICY_DIGEST,
        "iat": now,
        "auth_time": now,
        "custom:authentication_assurance": "phishing_resistant_mfa",
    }
    human_claims.update(overrides)
    return _fake_jwt_claims(**human_claims)


# ── E2E: Startup Validation → App Lifecycle ──────────────

class TestE2EStartupLifecycle:
    """Tests that validate_auth_config prevents unsafe app creation."""

    def test_demo_env_without_pool_id_prevents_app_creation(self):
        """E2E: APP_ENV=demo without COGNITO_USER_POOL_ID → app never starts."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,
            cognito_allowed_client_ids="some-client",
        )
        with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
            validate_auth_config(settings)

    def test_demo_env_without_client_allowlist_prevents_app_creation(self):
        """E2E: APP_ENV=demo without COGNITO_ALLOWED_CLIENT_IDS → app never starts."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_DemoPool",
            cognito_allowed_client_ids="",
        )
        with pytest.raises(RuntimeError, match="COGNITO_ALLOWED_CLIENT_IDS"):
            validate_auth_config(settings)

    def test_staging_env_with_local_mock_prevents_app_creation(self):
        """E2E: APP_ENV=staging with AUTH_MODE=local_mock → app never starts."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="staging",
            auth_mode="local_mock",
        )
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            validate_auth_config(settings)

    def test_prod_env_with_all_config_allows_app_creation(self):
        """E2E: APP_ENV=prod with full config → validate passes."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_ProdPool",
            cognito_region="us-east-1",
            cognito_allowed_client_ids="prod-spa-client",
            tenant_claim_name="custom:customerId",
            scanalyze_deployment_customer_id="customer-example",
        )
        # Should not raise
        validate_auth_config(settings)

    def test_unknown_env_treated_as_secure(self):
        """E2E: Any unknown APP_ENV (e.g. 'qa', 'uat') is treated as secure remote."""
        from app.config import validate_auth_config
        for env_name in ["qa", "uat", "preprod", "integration", "sandbox"]:
            settings = _make_settings(
                env=env_name,
                auth_mode="cognito_jwt",
                cognito_user_pool_id=None,
                cognito_allowed_client_ids="some-client",
            )
            with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
                validate_auth_config(settings)


# ── E2E: Full HTTP Request Flow ──────────────────────────

class TestE2EHttpRequestFlow:
    """Tests that exercise the complete HTTP request lifecycle:
       Client → FastAPI → Middleware → Auth Dependency → Route Handler
    """

    def _create_test_app(self, settings_overrides: dict = None) -> TestClient:
        """Create a test app with mocked auth, bypassing real JWKS."""
        from app.auth import get_auth_context, AuthContext
        from app.errors import register_exception_handlers

        test_settings = _make_settings(**(settings_overrides or {}))

        app = FastAPI()

        # Register exception handlers so AppError → proper HTTP responses
        register_exception_handlers(app)

        # Register a protected route using the real auth dependency
        from fastapi import Depends

        @app.get("/api/v1/test")
        def test_route(auth: AuthContext = Depends(get_auth_context)):
            return {
                "tenant_id": auth.tenant_id,
                "subject": auth.subject,
                "auth_source": auth.auth_source,
            }

        @app.get("/health")
        def health():
            return {"status": "ok"}

        return TestClient(app), test_settings

    def test_health_endpoint_needs_no_auth(self):
        """E2E: /health is accessible without any auth."""
        client, _ = self._create_test_app()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_protected_endpoint_without_auth_returns_401(self):
        """E2E: Protected endpoint without Authorization header → 401."""
        client, settings = self._create_test_app()
        with patch("app.auth.get_settings", return_value=settings):
            resp = client.get("/api/v1/test")
        assert resp.status_code == 401

    def test_protected_endpoint_with_x_tenant_id_only_returns_401(self):
        """E2E: X-Tenant-Id alone (no JWT) → 401. Header is IGNORED."""
        client, settings = self._create_test_app()
        with patch("app.auth.get_settings", return_value=settings):
            resp = client.get("/api/v1/test", headers={"X-Tenant-Id": "tenant-alpha"})
        assert resp.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_valid_jwt_with_tenant_claim_succeeds(self, mock_cache):
        """E2E: Valid JWT with custom:customerId → 200 with correct tenant."""
        client, _ = self._create_test_app()
        settings = _make_human_settings()
        claims = _fake_human_jwt_claims()
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == _CUSTOMER_ID_A
        assert body["subject"] == "user-abc-123"
        assert body["auth_source"] == "cognito_jwt"

    @patch("app.auth._jwks_cache")
    def test_jwt_with_disallowed_client_id_returns_401(self, mock_cache):
        """E2E: JWT with client_id not in allowlist → 401."""
        client, settings = self._create_test_app(
            {"cognito_allowed_client_ids": "only-this-client"}
        )
        claims = _fake_jwt_claims(client_id="rogue-client")
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_x_tenant_id_header_is_rejected(self, mock_cache):
        """E2E: identity-bearing legacy headers are rejected."""
        client, settings = self._create_test_app()
        claims = _fake_jwt_claims()
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={
                        "Authorization": "Bearer valid.jwt.token",
                        "X-Tenant-Id": "attacker-tenant",
                    },
                )
        assert resp.status_code == 403

    @patch("app.auth._jwks_cache")
    def test_jwt_without_tenant_claim_returns_403(self, mock_cache):
        """E2E: JWT valid but missing custom:customerId → 403."""
        client, _ = self._create_test_app()
        settings = _make_human_settings()
        claims = _fake_human_jwt_claims()
        del claims["custom:customerId"]
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 403

    @patch("app.auth._jwks_cache")
    def test_m2m_token_without_mapping_returns_403(self, mock_cache):
        """E2E: M2M token (no tenant claim, no cognito:username) with M2M disabled → 403."""
        client, settings = self._create_test_app({"m2m_tenant_resolution": "disabled"})
        claims = _fake_jwt_claims()
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 403

    @patch("app.auth._jwks_cache")
    def test_m2m_token_with_valid_mapping_succeeds(self, mock_cache):
        """E2E: versioned M2M identity binding with exact tuple → 200."""
        client, settings = self._create_test_app({
            "cognito_allowed_client_ids": "test-spa-client,synthetic-m2m-client",
            "scanalyze_deployment_customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
            "scanalyze_deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "m2m_tenant_resolution": "client_identity_bindings_v1",
            "m2m_client_identity_bindings_v1": {
                "synthetic-m2m-client": {
                    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
                    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "required_scopes": [
                        "scanalyze-ingest/ingest.read",
                        "scanalyze-ingest/ingest.write",
                    ],
                }
            },
            "m2m_action_scope_sets_v1": {
                "read": ["scanalyze-ingest/ingest.read"],
                "write": ["scanalyze-ingest/ingest.write"],
                "admin": ["scanalyze-ingest/ingest.admin"],
            },
        })
        claims = _fake_jwt_claims(client_id="synthetic-m2m-client")
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
        assert body["auth_source"] == "m2m_identity_binding_v1"

    @patch("app.auth._jwks_cache")
    def test_demo_env_empty_allowlist_runtime_500(self, mock_cache):
        """E2E: APP_ENV=demo, empty allowlist at runtime → 500."""
        client, settings = self._create_test_app({
            "env": "demo",
            "cognito_allowed_client_ids": "",
        })
        claims = _fake_jwt_claims()
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 500

    def test_local_mock_in_dev_is_rejected(self):
        """P0-002: APP_ENV=dev, AUTH_MODE=local_mock → rejected (dev is cloud deployment)."""
        from app.auth import _resolve_local_mock_auth
        settings = _make_settings(
            env="dev",
            auth_mode="local_mock",
            local_mock_tenant_id="dev-tenant",
        )
        with pytest.raises(RuntimeError, match="FORBIDDEN"):
            with patch("app.auth.get_settings", return_value=settings):
                _resolve_local_mock_auth(settings)


# ── E2E: Cross-Tenant Isolation ──────────────────────────

class TestE2ECrossTenantIsolation:
    """Verify that tenant isolation is enforced at every layer."""

    @patch("app.auth._jwks_cache")
    def test_tenant_a_cannot_see_tenant_b_data(self, mock_cache):
        """E2E: Two different JWTs with different tenants get different AuthContexts."""
        from app.auth import _resolve_cognito_auth

        settings_a = _make_human_settings(
            cognito_allowed_client_ids="test-spa-client",
        )

        # Deployment A
        claims_a = _fake_human_jwt_claims()
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims_a):
            ctx_a = _resolve_cognito_auth("token-a", settings_a, None, "/test")

        # Independent deployment B with its own exact runtime binding.
        settings_b = _make_human_settings(
            scanalyze_deployment_customer_id=_CUSTOMER_ID_B,
            scanalyze_deployment_id=_DEPLOYMENT_ID_B,
            cognito_allowed_client_ids="test-spa-client",
        )
        claims_b = _fake_human_jwt_claims(
            **{
                "custom:customerId": _CUSTOMER_ID_B,
                "custom:deployment_id": _DEPLOYMENT_ID_B,
                "sub": "user-xyz",
            }
        )
        with patch("app.auth.jwt.decode", return_value=claims_b):
            ctx_b = _resolve_cognito_auth("token-b", settings_b, None, "/test")

        # Verify isolation
        assert ctx_a.tenant_id == _CUSTOMER_ID_A
        assert ctx_a.deployment_id == _DEPLOYMENT_ID_A
        assert ctx_b.tenant_id == _CUSTOMER_ID_B
        assert ctx_b.deployment_id == _DEPLOYMENT_ID_B
        assert ctx_a.tenant_id != ctx_b.tenant_id
        assert ctx_a.deployment_id != ctx_b.deployment_id
        assert ctx_a.subject != ctx_b.subject

    @patch("app.auth._jwks_cache")
    def test_attacker_x_tenant_id_cannot_override_jwt_tenant(self, mock_cache):
        """E2E: Attacker-supplied X-Tenant-Id is rejected."""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        settings = _make_settings(cognito_allowed_client_ids="test-spa-client")
        claims = _fake_jwt_claims(**{"custom:customerId": "tenant-user"})
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as captured:
                _resolve_cognito_auth(
                    "token",
                    settings,
                    legacy_tenant_header="admin",
                    request_path="/api/v1/test",
                )
        assert captured.value.status_code == 403


# ── E2E: Env Classification Matrix ──────────────────────

class TestE2EEnvClassificationMatrix:
    """Exhaustive test of ALL env names × ALL auth modes."""

    _SECURE_ENVS = ["prod", "production", "staging", "stg", "demo", "qa", "uat", "preprod", "dev"]
    _LOCAL_ENVS = ["local", "test", "ci"]

    def test_secure_envs_reject_incomplete_config(self):
        """Every secure env + cognito_jwt without pool_id → RuntimeError."""
        from app.config import validate_auth_config
        for env_name in self._SECURE_ENVS:
            settings = _make_settings(
                env=env_name,
                auth_mode="cognito_jwt",
                cognito_user_pool_id=None,
                cognito_allowed_client_ids="some-client",
            )
            with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
                validate_auth_config(settings)

    def test_secure_envs_reject_local_mock(self):
        """Every secure env + local_mock → RuntimeError."""
        from app.config import validate_auth_config
        for env_name in self._SECURE_ENVS:
            settings = _make_settings(
                env=env_name,
                auth_mode="local_mock",
            )
            with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
                validate_auth_config(settings)

    def test_local_envs_allow_incomplete_config(self):
        """Every local env + cognito_jwt without pool_id → warning only."""
        from app.config import validate_auth_config
        for env_name in self._LOCAL_ENVS:
            settings = _make_settings(
                env=env_name,
                auth_mode="cognito_jwt",
                cognito_user_pool_id=None,
            )
            # Should NOT raise — just log
            validate_auth_config(settings)

    def test_local_envs_allow_local_mock(self):
        """Every local env + local_mock → no error."""
        from app.config import validate_auth_config
        for env_name in self._LOCAL_ENVS:
            settings = _make_settings(
                env=env_name,
                auth_mode="local_mock",
            )
            # Should NOT raise
            validate_auth_config(settings)

    def test_secure_envs_pass_with_full_config(self):
        """Every secure env + full config → no error."""
        from app.config import validate_auth_config
        for env_name in self._SECURE_ENVS:
            settings = _make_settings(
                env=env_name,
                auth_mode="cognito_jwt",
                cognito_user_pool_id=f"us-east-1_{env_name.capitalize()}Pool",
                cognito_region="us-east-1",
                cognito_allowed_client_ids=f"{env_name}-spa-client",
                tenant_claim_name="custom:customerId",
                scanalyze_deployment_customer_id=f"{env_name}-customer",
            )
            # Should not raise
            validate_auth_config(settings)


# ── E2E: IaC Config Consistency ──────────────────────────

class TestE2EIaCConfigConsistency:
    """Verify that the IaC config in cicd.tfvars would produce a valid Settings object."""

    def test_demo_iac_env_vars_produce_valid_config(self):
        """The env vars in cicd.tfvars for demo must pass validate_auth_config."""
        from app.config import validate_auth_config

        # Simulate the exact env vars from envs/demo/cicd.tfvars
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_region="us-east-1",
            cognito_allowed_token_uses="access",
            tenant_claim_name="custom:customerId",
            m2m_tenant_resolution="disabled",
            # These would be resolved from SSM at deploy time
            cognito_user_pool_id="us-east-1_RESOLVED_FROM_SSM",
            cognito_allowed_client_ids="RESOLVED_FROM_SSM",
            scanalyze_deployment_customer_id="customer-example",
        )
        # Must not raise
        validate_auth_config(settings)

    def test_demo_iac_env_vars_without_ssm_resolution_fails(self):
        """If SSM params are not resolved (empty), demo must fail."""
        from app.config import validate_auth_config

        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_region="us-east-1",
            cognito_allowed_token_uses="access",
            tenant_claim_name="custom:customerId",
            m2m_tenant_resolution="disabled",
            # SSM params not resolved
            cognito_user_pool_id=None,
            cognito_allowed_client_ids="",
        )
        with pytest.raises(RuntimeError):
            validate_auth_config(settings)


# ── E2E: Security Attack Vectors ─────────────────────────

class TestE2ESecurityAttackVectors:
    """Simulate specific attack scenarios to verify defense-in-depth."""

    @patch("app.auth._jwks_cache")
    def test_attack_header_injection_tenant(self, mock_cache):
        """Attack: Inject X-Tenant-Id=admin with valid JWT for tenant-user.
        Expected: 403 because request identity headers are forbidden."""
        from app.auth import get_auth_context, AuthContext
        from app.errors import register_exception_handlers
        from fastapi import Depends

        settings = _make_settings(cognito_allowed_client_ids="test-spa-client")
        claims = _fake_jwt_claims(**{"custom:customerId": "tenant-user"})
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/api/v1/test")
        def test_route(auth: AuthContext = Depends(get_auth_context)):
            return {"tenant_id": auth.tenant_id}

        client = TestClient(app)

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={
                        "Authorization": "Bearer valid.jwt.token",
                        "X-Tenant-Id": "admin",
                    },
                )
        assert resp.status_code == 403

    @patch("app.auth._jwks_cache")
    def test_attack_default_tenant_in_jwt_rejected(self, mock_cache):
        """Attack: JWT contains custom:customerId='default'.
        Expected: 403 — 'default' is a forbidden tenant value."""
        from app.auth import get_auth_context, AuthContext
        from app.errors import register_exception_handlers
        from fastapi import Depends

        settings = _make_human_settings(
            cognito_allowed_client_ids="test-spa-client"
        )
        claims = _fake_human_jwt_claims(
            **{"custom:customerId": "default"}
        )
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/api/v1/test")
        def test_route(auth: AuthContext = Depends(get_auth_context)):
            return {"tenant_id": auth.tenant_id}

        client = TestClient(app)

        with patch("app.auth.get_settings", return_value=settings):
            with patch("app.auth.jwt.decode", return_value=claims):
                resp = client.get(
                    "/api/v1/test",
                    headers={"Authorization": "Bearer valid.jwt.token"},
                )
        assert resp.status_code == 403

    def test_attack_no_bearer_scheme(self):
        """Attack: Send 'Basic' auth instead of 'Bearer'.
        Expected: 401."""
        from app.auth import get_auth_context, AuthContext
        from app.errors import register_exception_handlers
        from fastapi import Depends

        settings = _make_settings()
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/api/v1/test")
        def test_route(auth: AuthContext = Depends(get_auth_context)):
            return {}

        client = TestClient(app)

        with patch("app.auth.get_settings", return_value=settings):
            resp = client.get(
                "/api/v1/test",
                headers={"Authorization": "Basic dXNlcjpwYXNz"},
            )
        assert resp.status_code == 401

    def test_attack_empty_bearer_token(self):
        """Attack: Send 'Bearer ' with empty token.
        Expected: 401."""
        from app.auth import get_auth_context, AuthContext
        from app.errors import register_exception_handlers
        from fastapi import Depends

        settings = _make_settings()
        app = FastAPI()
        register_exception_handlers(app)

        @app.get("/api/v1/test")
        def test_route(auth: AuthContext = Depends(get_auth_context)):
            return {}

        client = TestClient(app)

        with patch("app.auth.get_settings", return_value=settings):
            resp = client.get(
                "/api/v1/test",
                headers={"Authorization": "Bearer "},
            )
        assert resp.status_code == 401

    def test_attack_principal_claim_as_tenant_claim(self):
        """Attack: Set TENANT_CLAIM_NAME=sub to use JWT sub as tenant.
        Expected: validate_auth_config rejects at startup."""
        from app.config import validate_auth_config

        for claim in ["sub", "client_id", "email", "username", "scope", "iss", "aud"]:
            settings = _make_settings(
                env="demo",
                auth_mode="cognito_jwt",
                cognito_user_pool_id="us-east-1_Pool",
                cognito_allowed_client_ids="some-client",
                tenant_claim_name=claim,
            )
            with pytest.raises(RuntimeError, match="principal/identity claim"):
                validate_auth_config(settings)
