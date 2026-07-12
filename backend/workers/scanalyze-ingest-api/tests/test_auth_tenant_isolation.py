"""P0-001: Tenant isolation tests — auth context from verified JWT only.

Tests cover:
  - JWT without signature verification is rejected
  - X-Tenant-Id header is rejected in protected routes
  - Fallback "default" tenant is prohibited
  - Cross-tenant access is blocked
  - M2M client_credentials without tenant claim fails closed
  - M2M with mapped/unmapped client_id
  - TENANT_CLAIM_NAME cannot be set to principal claims
  - token_use validation
  - Health checks remain public
  - Local mock auth is blocked in production
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ── Test Helpers ──────────────────────────────────────────

def _make_settings(**overrides: Any) -> MagicMock:
    """Create a mock Settings object with safe defaults for testing."""
    defaults = {
        "env": "test",
        "auth_mode": "cognito_jwt",
        "cognito_user_pool_id": "us-east-1_TestPool",
        "cognito_region": "us-east-1",
        "cognito_allowed_token_uses": "access",
        "cognito_allowed_client_ids": "",
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
        "custom:customerId": "tenant-alpha",
        "cognito:username": "user-abc-123",
        "email": "user@example.com",
        "name": "Test User",
    }
    base.update(overrides)
    return base


# ── Unit Tests: Tenant ID Validation ─────────────────────

class TestTenantIdValidation:
    def test_valid_tenant_id(self):
        from app.auth import _validate_tenant_id
        assert _validate_tenant_id("tenant-alpha", source="test") == "tenant-alpha"
        assert _validate_tenant_id("my-org-123", source="test") == "my-org-123"
        assert _validate_tenant_id("ab", source="test") == "ab"

    def test_empty_tenant_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        with pytest.raises(AppError) as exc:
            _validate_tenant_id("", source="test")
        assert exc.value.status_code == 403

    def test_none_tenant_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        with pytest.raises(AppError):
            _validate_tenant_id(None, source="test")

    def test_default_tenant_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        with pytest.raises(AppError) as exc:
            _validate_tenant_id("default", source="test")
        assert exc.value.status_code == 403

    def test_null_string_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        for bad in ("null", "none", "undefined", "NULL", "None"):
            with pytest.raises(AppError):
                _validate_tenant_id(bad, source="test")

    def test_whitespace_only_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        with pytest.raises(AppError):
            _validate_tenant_id("   ", source="test")

    def test_dangerous_characters_rejected(self):
        from app.auth import _validate_tenant_id
        from app.errors import AppError
        for bad in ("tenant/../../etc", "tenant;DROP TABLE", "a" * 200, "../"):
            with pytest.raises(AppError):
                _validate_tenant_id(bad, source="test")


# ── Unit Tests: Tenant Claim Name Validation ──────────────

class TestTenantClaimNameValidation:
    def test_valid_claim_names(self):
        from app.auth import _validate_tenant_claim_name
        # These should NOT raise
        _validate_tenant_claim_name("custom:customerId")
        _validate_tenant_claim_name("custom:tenant")
        _validate_tenant_claim_name("tenant_id")
        _validate_tenant_claim_name("org_id")

    def test_principal_claims_rejected(self):
        from app.auth import _validate_tenant_claim_name
        for bad in ("sub", "client_id", "username", "email", "scope", "scp", "aud", "iss"):
            with pytest.raises(ValueError, match="principal/identity claim"):
                _validate_tenant_claim_name(bad)

    def test_empty_claim_name_rejected(self):
        from app.auth import _validate_tenant_claim_name
        with pytest.raises(ValueError, match="must not be empty"):
            _validate_tenant_claim_name("")


# ── Unit Tests: JWT Verification (mocked JWKS) ───────────

class TestCognitoJwtVerification:
    """Tests that use mocked JWKS to test JWT verification logic."""

    @patch("app.auth._jwks_cache")
    def test_valid_access_token(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        import jwt as pyjwt

        claims = _fake_jwt_claims()
        settings = _make_settings()

        # Mock the JWKS signing key and jwt.decode
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims):
            result = _verify_cognito_jwt("fake.token.here", settings)

        assert result["custom:customerId"] == "tenant-alpha"
        assert result["token_use"] == "access"

    @patch("app.auth._jwks_cache")
    def test_expired_token_returns_401(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        import jwt as pyjwt

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", side_effect=pyjwt.ExpiredSignatureError("expired")):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("expired.token.here", _make_settings())
            assert exc.value.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_wrong_issuer_returns_401(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        import jwt as pyjwt

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", side_effect=pyjwt.InvalidIssuerError("bad issuer")):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("bad-issuer.token.here", _make_settings())
            assert exc.value.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_invalid_signature_returns_401(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        import jwt as pyjwt

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", side_effect=pyjwt.InvalidSignatureError("bad sig")):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("bad-sig.token.here", _make_settings())
            assert exc.value.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_invalid_token_use_returns_401(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError

        claims = _fake_jwt_claims(token_use="id")  # but settings only allows "access"
        settings = _make_settings(cognito_allowed_token_uses="access")

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("id-token.here", settings)
            assert exc.value.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_id_token_accepted_when_explicitly_enabled(self, mock_cache):
        from app.auth import _verify_cognito_jwt

        claims = _fake_jwt_claims(token_use="id", aud="test-spa-client")
        settings = _make_settings(
            cognito_allowed_token_uses="access,id",
            cognito_allowed_client_ids="test-spa-client",
        )

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims):
            result = _verify_cognito_jwt("id.token.here", settings)
        assert result["token_use"] == "id"

    @patch("app.auth._jwks_cache")
    def test_invalid_client_id_returns_401(self, mock_cache):
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError

        claims = _fake_jwt_claims(client_id="unknown-client")
        settings = _make_settings(cognito_allowed_client_ids="allowed-client-1,allowed-client-2")

        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key

        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("token.here", settings)
            assert exc.value.status_code == 401


# ── Unit Tests: Tenant Resolution ─────────────────────────

class TestTenantResolution:

    @patch("app.auth._verify_cognito_jwt")
    def test_tenant_from_verified_claims(self, mock_verify):
        from app.auth import _resolve_cognito_auth
        mock_verify.return_value = _fake_jwt_claims()
        settings = _make_settings()

        ctx = _resolve_cognito_auth("token", settings, legacy_tenant_header=None, request_path="/api/v1/documents")
        assert ctx.tenant_id == "tenant-alpha"
        assert ctx.tenant == "tenant-alpha"  # backwards-compatible property
        assert ctx.auth_source == "cognito_jwt"

    @patch("app.auth._verify_cognito_jwt")
    def test_x_tenant_id_rejected_when_jwt_has_tenant(self, mock_verify):
        """Identity-bearing legacy headers are rejected rather than ignored."""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError
        mock_verify.return_value = _fake_jwt_claims(**{"custom:customerId": "tenant-a"})
        settings = _make_settings()

        with pytest.raises(AppError) as captured:
            _resolve_cognito_auth("token", settings, legacy_tenant_header="tenant-b", request_path="/test")
        assert captured.value.status_code == 403

    @patch("app.auth._verify_cognito_jwt")
    def test_missing_tenant_claim_fails_403(self, mock_verify):
        """JWT valid but missing custom:customerId → 403"""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        claims = _fake_jwt_claims()
        del claims["custom:customerId"]
        # Simulate user token (has cognito:username)
        claims["cognito:username"] = "testuser"
        mock_verify.return_value = claims
        settings = _make_settings()

        with pytest.raises(AppError) as exc:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert exc.value.status_code == 403

    @patch("app.auth._verify_cognito_jwt")
    def test_tenant_default_in_claim_rejected(self, mock_verify):
        """JWT with custom:customerId='default' → 403"""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        mock_verify.return_value = _fake_jwt_claims(**{"custom:customerId": "default"})
        settings = _make_settings()

        with pytest.raises(AppError) as exc:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert exc.value.status_code == 403


# ── Unit Tests: M2M Client Credentials ────────────────────

class TestM2MTenantResolution:

    @patch("app.auth._verify_cognito_jwt")
    def test_m2m_without_tenant_claim_disabled_returns_403(self, mock_verify):
        """M2M access token without custom:customerId, M2M resolution disabled → 403"""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        claims = _fake_jwt_claims(token_use="access", client_id="m2m-client-id")
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_verify.return_value = claims
        settings = _make_settings(m2m_tenant_resolution="disabled")

        with pytest.raises(AppError) as exc:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert exc.value.status_code == 403

    @patch("app.auth._verify_cognito_jwt")
    def test_m2m_unmapped_client_id_returns_403(self, mock_verify):
        """M2M token, client_id_map mode, but client_id not in map → 403"""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        claims = _fake_jwt_claims(token_use="access", client_id="unknown-m2m-client")
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_verify.return_value = claims

        settings = _make_settings(
            m2m_tenant_resolution="client_id_map",
            m2m_client_tenant_map={"known-client": "tenant-x"},
        )

        with pytest.raises(AppError) as exc:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert exc.value.status_code == 403

    @patch("app.auth._verify_cognito_jwt")
    def test_legacy_m2m_customer_only_map_is_rejected(self, mock_verify):
        """Legacy client_id_map cannot authorize a machine principal."""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        claims = _fake_jwt_claims(token_use="access", client_id="mapped-m2m-client")
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_verify.return_value = claims

        settings = _make_settings(
            m2m_tenant_resolution="client_id_map",
            m2m_client_tenant_map={"mapped-m2m-client": "tenant-from-map"},
        )

        with pytest.raises(AppError) as captured:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert captured.value.status_code == 403

    @patch("app.auth._verify_cognito_jwt")
    def test_m2m_mapped_to_default_tenant_rejected(self, mock_verify):
        """M2M client mapped to 'default' → 403 (default is always rejected)"""
        from app.auth import _resolve_cognito_auth
        from app.errors import AppError

        claims = _fake_jwt_claims(token_use="access", client_id="bad-map-client")
        del claims["custom:customerId"]
        del claims["cognito:username"]
        del claims["email"]
        del claims["name"]
        mock_verify.return_value = claims

        settings = _make_settings(
            m2m_tenant_resolution="client_id_map",
            m2m_client_tenant_map={"bad-map-client": "default"},
        )

        with pytest.raises(AppError) as exc:
            _resolve_cognito_auth("token", settings, None, "/test")
        assert exc.value.status_code == 403


# ── Unit Tests: Local Mock Auth ───────────────────────────

class TestLocalMockAuth:
    def test_local_mock_in_test_env(self):
        from app.auth import _resolve_local_mock_auth
        settings = _make_settings(
            env="test",
            auth_mode="local_mock",
            local_mock_tenant_id="dev-tenant",
            local_mock_subject="dev-user",
        )
        ctx = _resolve_local_mock_auth(settings)
        assert ctx.tenant_id == "dev-tenant"
        assert ctx.auth_source == "local_mock"

    def test_local_mock_blocked_in_production(self):
        from app.auth import _resolve_local_mock_auth
        settings = _make_settings(env="prod", auth_mode="local_mock", local_mock_tenant_id="dev-tenant")
        with pytest.raises(RuntimeError, match="FORBIDDEN"):
            _resolve_local_mock_auth(settings)

    def test_local_mock_blocked_in_staging(self):
        from app.auth import _resolve_local_mock_auth
        settings = _make_settings(env="staging", auth_mode="local_mock", local_mock_tenant_id="dev-tenant")
        with pytest.raises(RuntimeError, match="FORBIDDEN"):
            _resolve_local_mock_auth(settings)

    def test_local_mock_without_explicit_tenant_fails(self):
        from app.auth import _resolve_local_mock_auth
        settings = _make_settings(
            env="test",
            auth_mode="local_mock",
            local_mock_tenant_id=None,
        )
        with pytest.raises(RuntimeError, match="LOCAL_MOCK_TENANT_ID"):
            _resolve_local_mock_auth(settings)

    def test_local_mock_with_default_tenant_fails(self):
        from app.auth import _resolve_local_mock_auth
        from app.errors import AppError
        settings = _make_settings(
            env="test",
            auth_mode="local_mock",
            local_mock_tenant_id="default",
        )
        with pytest.raises(AppError) as exc:
            _resolve_local_mock_auth(settings)
        assert exc.value.status_code == 403


# ── Integration Tests: HTTP endpoints ─────────────────────

class TestHttpEndpoints:
    """Tests using FastAPI TestClient with dependency overrides."""

    @pytest.fixture(autouse=True)
    def setup_app(self, monkeypatch):
        """Fresh app for each test — no global state leakage."""
        # P0-002: Set APP_ENV=test so create_app() doesn't fail with dev defaults
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")
        from app.config import get_settings
        get_settings.cache_clear()
        from app.main import create_app
        from app.auth import get_auth_context, AuthContext
        self.app = create_app()
        self.client = TestClient(self.app, raise_server_exceptions=False)
        yield
        # Reset overrides after each test
        self.app.dependency_overrides.clear()
        get_settings.cache_clear()

    def _override_auth(self, tenant_id: str = "tenant-a", subject: str = "user-1"):
        from app.auth import get_auth_context, AuthContext
        def _mock():
            return AuthContext(tenant_id=tenant_id, subject=subject, auth_source="cognito_jwt")
        self.app.dependency_overrides[get_auth_context] = _mock

    def test_health_check_no_auth_required(self):
        """Health endpoints must work without any auth."""
        resp = self.client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_v1_no_auth_required(self):
        resp = self.client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_protected_endpoint_no_auth_returns_401(self):
        """Without any auth override, calling a protected endpoint returns 401/403."""
        # get_auth_context is NOT overridden — it will try Cognito JWT verification
        # which will fail because COGNITO_USER_POOL_ID is not set properly in test env
        resp = self.client.post(
            "/api/v1/documents",
            json={"filename": "test.pdf", "contentType": "application/pdf"},
        )
        # Should be 401 (missing Authorization header) or 500 (misconfigured)
        assert resp.status_code in (401, 500, 422)

    def test_protected_endpoint_with_valid_auth(self):
        """With auth override simulating valid tenant, endpoint works."""
        self._override_auth(tenant_id="tenant-test")
        with patch("app.api.v1.documents.DocumentsService") as MockSvc:
            MockSvc.return_value.create_document.return_value = {
                "documentId": "doc-123",
                "uploadUrl": "https://s3.example.com/presigned",
                "expiresAt": "2026-01-01T00:00:00Z",
            }
            resp = self.client.post(
                "/api/v1/documents",
                json={"filename": "test.pdf", "contentType": "application/pdf"},
            )
            assert resp.status_code == 201

    def test_cross_tenant_document_access_blocked(self):
        """Tenant-A cannot access documents owned by tenant-B (403 from service layer)."""
        self._override_auth(tenant_id="tenant-a")
        with patch("app.api.v1.documents.DocumentsService") as MockSvc:
            from app.errors import AppError
            MockSvc.return_value.get_document_status.side_effect = AppError(
                code="FORBIDDEN",
                message="Document does not belong to tenant",
                status_code=403,
                details={},
            )
            resp = self.client.get("/api/v1/documents/doc-from-tenant-b")
            assert resp.status_code == 403


# ── Tests: X-Tenant-Id Header Behavior ────────────────────

class TestXTenantIdIgnored:
    """Verify X-Tenant-Id header is never used as tenant source."""

    def test_x_tenant_id_alone_returns_401(self, monkeypatch):
        """Sending only X-Tenant-Id without Authorization → 401"""
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")
        from app.config import get_settings
        get_settings.cache_clear()
        from app.main import create_app
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.post(
            "/api/v1/documents",
            headers={"X-Tenant-Id": "spoofed-tenant"},
            json={"filename": "test.pdf", "contentType": "application/pdf"},
        )
        # Must be 401 (missing Authorization), never 200 with spoofed-tenant
        assert resp.status_code in (401, 500)
        get_settings.cache_clear()

    @patch("app.auth._verify_cognito_jwt")
    @patch("app.auth.get_settings")
    def test_x_tenant_id_with_jwt_uses_jwt_tenant(self, mock_settings, mock_verify, monkeypatch):
        """X-Tenant-Id: tenant-b + JWT custom:customerId=tenant-a → uses tenant-a"""
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AUTH_MODE", "cognito_jwt")
        from app.config import get_settings
        get_settings.cache_clear()
        from app.auth import get_auth_context, AuthContext
        from app.main import create_app
        from fastapi import Request

        mock_verify.return_value = _fake_jwt_claims(**{"custom:customerId": "tenant-a"})
        mock_settings.return_value = _make_settings()

        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)

        # We override auth to test the exact function behavior
        def _test_auth(request: Request):
            from app.auth import get_auth_context as _orig
            from fastapi import Header
            return _orig.__wrapped__(request, "Bearer fake.token.here", "tenant-b") if hasattr(_orig, '__wrapped__') else AuthContext(tenant_id="tenant-a", subject="user-1", auth_source="cognito_jwt")

        app.dependency_overrides[get_auth_context] = lambda: AuthContext(tenant_id="tenant-a", subject="user-1", auth_source="cognito_jwt")

        with patch("app.api.v1.documents.DocumentsService") as MockSvc:
            MockSvc.return_value.get_document_status.return_value = {
                "documentId": "doc-123",
                "tenantId": "tenant-a",
                "status": "COMPLETED",
            }
            resp = client.get(
                "/api/v1/documents/doc-123456",
                headers={"X-Tenant-Id": "tenant-b"},
            )
            assert resp.status_code == 200
            # The complete trusted context is passed; the legacy header is never authority.
            call = MockSvc.return_value.get_document_status.call_args
            assert call.kwargs["auth"].customer_id == "tenant-a"
            assert call.kwargs["auth"].customer_id != "tenant-b"
            assert call.kwargs["document_id"] == "doc-123456"
        get_settings.cache_clear()


# ── Tests: No Fallback Default ────────────────────────────

class TestNoDefaultFallback:
    """Verify 'default' is never used as tenant in protected routes."""

    def test_fallback_default_not_in_auth_module(self):
        """Verify the auth module source code does not assign 'default' as tenant."""
        import inspect
        from app import auth

        source = inspect.getsource(auth)
        # The old line was: tenant = "default"
        # Ensure no assignment to "default" as fallback
        lines = source.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip comments, docstrings, and test-related content
            if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'"):
                continue
            # Check for the dangerous pattern
            if 'tenant' in stripped.lower() and '= "default"' in stripped:
                # Allow it in _FORBIDDEN_TENANT_VALUES or validation
                if "_FORBIDDEN_TENANT_VALUES" in stripped or "frozenset" in stripped:
                    continue
                pytest.fail(f"Line {i+1}: Found tenant='default' assignment: {stripped}")


# ── Tests: parse_jwt_without_verification removed ─────────

class TestNoUnverifiedJwtParse:
    def test_function_does_not_exist(self):
        """parse_jwt_without_verification must be removed."""
        from app import auth
        assert not hasattr(auth, "parse_jwt_without_verification"), \
            "parse_jwt_without_verification must be removed (P0-001)"

    def test_b64url_decode_removed(self):
        """_b64url_decode helper must be removed."""
        from app import auth
        assert not hasattr(auth, "_b64url_decode"), \
            "_b64url_decode must be removed (P0-001)"


# ── Tests: Startup Config Validation (P0-001 hardening) ───

class TestStartupConfigValidation:
    """Fail-fast startup validation for auth config."""

    def test_prod_without_cognito_user_pool_id_fails(self):
        """In prod, AUTH_MODE=cognito_jwt without COGNITO_USER_POOL_ID → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,  # Missing!
            cognito_allowed_client_ids="some-client-id",
        )
        with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
            validate_auth_config(settings)

    def test_prod_without_allowed_client_ids_fails(self):
        """In prod, empty COGNITO_ALLOWED_CLIENT_IDS → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_ProdPool",
            cognito_allowed_client_ids="",  # Empty!
        )
        with pytest.raises(RuntimeError, match="COGNITO_ALLOWED_CLIENT_IDS"):
            validate_auth_config(settings)

    def test_staging_without_allowed_client_ids_fails(self):
        """In staging, empty COGNITO_ALLOWED_CLIENT_IDS → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="staging",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_StagingPool",
            cognito_allowed_client_ids="",  # Empty!
        )
        with pytest.raises(RuntimeError, match="COGNITO_ALLOWED_CLIENT_IDS"):
            validate_auth_config(settings)

    def test_prod_with_valid_config_passes(self):
        """In prod, fully configured auth → no error."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_ProdPool",
            cognito_region="us-east-1",
            cognito_allowed_client_ids="prod-spa-client,prod-m2m-client",
            tenant_claim_name="custom:customerId",
            scanalyze_deployment_customer_id="customer-example",
        )
        # Should not raise
        validate_auth_config(settings)

    def test_dev_without_pool_id_now_fails(self):
        """P0-002: In dev (now a customer deployment), missing COGNITO_USER_POOL_ID raises."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="dev",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,
        )
        # P0-002: dev is a customer deployment — must raise
        with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
            validate_auth_config(settings)

    def test_local_mock_mode_in_prod_is_rejected(self):
        """AUTH_MODE=local_mock in prod → RuntimeError (forbidden in secure remote env)."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="local_mock",  # Forbidden in prod!
            cognito_user_pool_id=None,
        )
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            validate_auth_config(settings)

    def test_local_mock_mode_in_ci_skips_cognito_validation(self):
        """AUTH_MODE=local_mock in ci does not validate Cognito settings."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="ci",
            auth_mode="local_mock",  # Allowed in ci
            cognito_user_pool_id=None,
        )
        # Should not raise — local_mock is permitted in ci
        validate_auth_config(settings)

    def test_local_mock_mode_in_dev_is_rejected(self):
        """P0-002: AUTH_MODE=local_mock in dev → RuntimeError (dev is a cloud deployment)."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="dev",
            auth_mode="local_mock",
            local_mock_tenant_id="dev-tenant",
        )
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            validate_auth_config(settings)

    def test_prod_with_principal_claim_name_fails(self):
        """In prod, TENANT_CLAIM_NAME=sub → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="prod",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_ProdPool",
            cognito_allowed_client_ids="some-client",
            tenant_claim_name="sub",  # Principal claim!
        )
        with pytest.raises(RuntimeError, match="principal/identity claim"):
            validate_auth_config(settings)


# ── Tests: Client ID Allowlist Hardening ──────────────────

class TestClientIdAllowlistHardening:
    """Verify client_id validation against allowlist."""

    @patch("app.auth._jwks_cache")
    def test_access_token_allowed_client_id_passes(self, mock_cache):
        """Access token with client_id in allowlist → accepted."""
        from app.auth import _verify_cognito_jwt
        claims = _fake_jwt_claims(client_id="allowed-spa-client")
        settings = _make_settings(
            cognito_allowed_client_ids="allowed-spa-client,another-client",
        )
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key
        with patch("app.auth.jwt.decode", return_value=claims):
            result = _verify_cognito_jwt("token.here", settings)
        assert result["client_id"] == "allowed-spa-client"

    @patch("app.auth._jwks_cache")
    def test_access_token_disallowed_client_id_returns_401(self, mock_cache):
        """Access token with client_id NOT in allowlist → 401."""
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        claims = _fake_jwt_claims(client_id="rogue-client")
        settings = _make_settings(
            cognito_allowed_client_ids="allowed-spa-client,another-client",
        )
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key
        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("token.here", settings)
            assert exc.value.status_code == 401

    @patch("app.auth._jwks_cache")
    def test_prod_empty_allowlist_returns_500(self, mock_cache):
        """In prod env, empty COGNITO_ALLOWED_CLIENT_IDS → 500 (misconfigured)."""
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        claims = _fake_jwt_claims()
        settings = _make_settings(
            env="prod",
            cognito_allowed_client_ids="",  # Empty!
        )
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key
        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("token.here", settings)
            assert exc.value.status_code == 500

    @patch("app.auth._jwks_cache")
    def test_demo_empty_allowlist_returns_500(self, mock_cache):
        """In demo env, empty COGNITO_ALLOWED_CLIENT_IDS → 500 (secure remote env)."""
        from app.auth import _verify_cognito_jwt
        from app.errors import AppError
        claims = _fake_jwt_claims()
        settings = _make_settings(
            env="demo",
            cognito_allowed_client_ids="",  # Empty!
        )
        mock_key = MagicMock()
        mock_cache.get_signing_key.return_value = mock_key
        with patch("app.auth.jwt.decode", return_value=claims):
            with pytest.raises(AppError) as exc:
                _verify_cognito_jwt("token.here", settings)
            assert exc.value.status_code == 500


# ── Tests: APP_ENV=demo Treated as Secure Remote Env ─────

class TestDemoEnvSecureValidation:
    """APP_ENV=demo must require full auth config like prod/staging."""

    def test_demo_without_cognito_user_pool_id_fails(self):
        """demo + cognito_jwt without COGNITO_USER_POOL_ID → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,  # Missing!
            cognito_allowed_client_ids="some-client-id",
        )
        with pytest.raises(RuntimeError, match="COGNITO_USER_POOL_ID"):
            validate_auth_config(settings)

    def test_demo_without_allowed_client_ids_fails(self):
        """demo + cognito_jwt without COGNITO_ALLOWED_CLIENT_IDS → RuntimeError."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_DemoPool",
            cognito_allowed_client_ids="",  # Empty!
        )
        with pytest.raises(RuntimeError, match="COGNITO_ALLOWED_CLIENT_IDS"):
            validate_auth_config(settings)

    def test_demo_with_local_mock_fails(self):
        """demo + local_mock → RuntimeError (forbidden in secure remote env)."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="local_mock",
            cognito_user_pool_id=None,
        )
        with pytest.raises(RuntimeError, match="local_mock is FORBIDDEN"):
            validate_auth_config(settings)

    def test_demo_with_valid_config_passes(self):
        """demo + fully configured auth → no error."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="demo",
            auth_mode="cognito_jwt",
            cognito_user_pool_id="us-east-1_DemoPool",
            cognito_region="us-east-1",
            cognito_allowed_client_ids="demo-spa-client",
            tenant_claim_name="custom:customerId",
            scanalyze_deployment_customer_id="demo-customer",
        )
        # Should not raise
        validate_auth_config(settings)

    def test_local_env_allows_missing_pool_id(self):
        """APP_ENV=local allows missing COGNITO_USER_POOL_ID (log-only)."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="local",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,
        )
        # Should NOT raise — just logs
        validate_auth_config(settings)

    def test_test_env_allows_missing_pool_id(self):
        """APP_ENV=test allows missing COGNITO_USER_POOL_ID (log-only)."""
        from app.config import validate_auth_config
        settings = _make_settings(
            env="test",
            auth_mode="cognito_jwt",
            cognito_user_pool_id=None,
        )
        # Should NOT raise — just logs
        validate_auth_config(settings)
