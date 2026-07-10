"""Customer-aware authentication context for Scanalyze Ingest API.

P0-001: Customer identity derived from verified auth — never from client-supplied headers.

Design decisions:
- JWT signature verified cryptographically against Cognito JWKS (RS256).
- Customer identity extracted exclusively from verified JWT claims (e.g. custom:customerId).
- X-Tenant-Id header is IGNORED in protected routes; presence is logged.
- Fallback to "default" customer is PROHIBITED in protected routes.
- M2M (client_credentials) tokens that lack a customer claim use an explicit
  server-side client_id→customer_id mapping (M2M_CLIENT_TENANT_MAP).
- Local/dev mock auth is gated by AUTH_MODE=local_mock AND APP_ENV∈{local,test,ci}.
- P0-002: Verified JWT custom:customerId must match SCANALYZE_DEPLOYMENT_CUSTOMER_ID.

NOTE (ADR): custom:customerId represents the SaaS CUSTOMER identity (e.g. customer-example),
  NOT a document processing route (platform/personal/gov/bank). Resource routing
  uses SCANALYZE_TENANT (env/config), not the JWT customer claim.
  See: _NotebookLM_Brain/05_ADR_Modelo_SaaS_Multi_Account.md
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional

import jwt  # PyJWT
from fastapi import Header, Request

from .config import get_settings
from .errors import AppError
from .logging import get_logger

# ── Constants ──────────────────────────────────────────────

_TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,126}[a-zA-Z0-9]$")
_FORBIDDEN_TENANT_VALUES = frozenset({"default", "null", "none", "undefined", ""})
_JWKS_CACHE_TTL_SECONDS = 300  # 5 min
_ALLOWED_TENANT_CLAIM_PREFIXES = ("custom:", "tenant", "org")
_DISALLOWED_TENANT_CLAIM_NAMES = frozenset({
    "sub", "client_id", "username", "email", "scope", "scp",
    "iss", "aud", "exp", "iat", "nbf", "jti", "token_use",
    "auth_time", "at_hash", "cognito:username", "cognito:groups",
    "event_id", "origin_jti",
})

logger = get_logger()


# ── Data Classes ───────────────────────────────────────────

@dataclass(frozen=True)
class AuthContext:
    """Verified authentication context for a request.

    NOTE: tenant_id is a LEGACY field name. Semantically it carries the
    SaaS customer_id (e.g. customer-example), NOT a document processing route
    (platform/personal/gov/bank). Resource routing is determined by
    SCANALYZE_TENANT env var, not this field.
    See ADR: 05_ADR_Modelo_SaaS_Multi_Account.
    """
    tenant_id: str  # Legacy name. Semantically = customer_id (e.g. customer-example)
    subject: Optional[str] = None
    scopes: list = field(default_factory=list)
    email: Optional[str] = None
    name: Optional[str] = None
    auth_source: str = "cognito_jwt"  # "cognito_jwt" | "m2m_client_map" | "local_mock"

    @property
    def customer_id(self) -> str:
        """SaaS customer identity (preferred over tenant_id)."""
        return self.tenant_id

    # Backwards-compatible alias used by all existing route handlers
    @property
    def tenant(self) -> str:
        return self.tenant_id


# ── Tenant ID Validation ──────────────────────────────────

def _validate_tenant_id(tenant_id: str, *, source: str) -> str:
    """Validate tenant_id format. Raises AppError(403) on invalid values."""
    if not tenant_id or not isinstance(tenant_id, str):
        logger.warning("tenant_validation_failed", reason="empty_or_null", source=source)
        raise AppError(
            code="FORBIDDEN",
            message="Tenant identifier is missing or invalid",
            status_code=403,
            details={},
        )

    cleaned = tenant_id.strip()

    if cleaned.lower() in _FORBIDDEN_TENANT_VALUES:
        logger.warning(
            "tenant_validation_failed",
            reason="forbidden_value",
            source=source,
            tenant_prefix=cleaned[:4] if len(cleaned) >= 4 else "***",
        )
        raise AppError(
            code="FORBIDDEN",
            message="Tenant identifier is not allowed",
            status_code=403,
            details={},
        )

    if not _TENANT_ID_PATTERN.match(cleaned):
        logger.warning(
            "tenant_validation_failed",
            reason="invalid_format",
            source=source,
            tenant_length=len(cleaned),
        )
        raise AppError(
            code="FORBIDDEN",
            message="Tenant identifier has invalid format",
            status_code=403,
            details={},
        )

    return cleaned


def _validate_tenant_claim_name(claim_name: str) -> None:
    """Ensure TENANT_CLAIM_NAME is a legitimate customer/tenant claim, not a principal claim.

    NOTE: TENANT_CLAIM_NAME is a legacy env var name. Semantically it specifies
    the JWT claim that carries the SaaS customer_id (e.g. custom:customerId).
    """
    if not claim_name:
        raise ValueError("TENANT_CLAIM_NAME must not be empty")

    normalized = claim_name.lower().strip()
    if normalized in _DISALLOWED_TENANT_CLAIM_NAMES:
        raise ValueError(
            f"TENANT_CLAIM_NAME='{claim_name}' is a principal/identity claim, "
            f"not a customer/tenant claim. Use an explicit customer claim like "
            f"custom:customerId, custom:tenantId, tenant_id, or org_id."
        )


# ── JWKS Cache ─────────────────────────────────────────────

class _JWKSCache:
    """Thread-safe JWKS cache with TTL."""
    def __init__(self) -> None:
        self._client: Optional[jwt.PyJWKClient] = None
        self._issuer: Optional[str] = None
        self._created_at: float = 0

    def get_signing_key(self, token: str, issuer_url: str) -> Any:
        now = time.monotonic()
        if (
            self._client is None
            or self._issuer != issuer_url
            or (now - self._created_at) > _JWKS_CACHE_TTL_SECONDS
        ):
            jwks_url = f"{issuer_url}/.well-known/jwks.json"
            self._client = jwt.PyJWKClient(jwks_url, cache_keys=True)
            self._issuer = issuer_url
            self._created_at = now

        return self._client.get_signing_key_from_jwt(token)


_jwks_cache = _JWKSCache()


# ── JWT Verification ───────────────────────────────────────

def _build_cognito_issuer(region: str, user_pool_id: str) -> str:
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"


def _verify_cognito_jwt(token: str, settings: Any) -> Dict[str, Any]:
    """Verify a Cognito JWT cryptographically and return validated claims.

    Raises AppError(401) on any verification failure.
    Does NOT log the token value.
    """
    issuer_url = _build_cognito_issuer(settings.cognito_region, settings.cognito_user_pool_id)

    # Determine allowed token_use values
    allowed_token_uses: List[str] = []
    raw = getattr(settings, "cognito_allowed_token_uses", "access")
    if raw:
        allowed_token_uses = [t.strip().lower() for t in raw.split(",") if t.strip()]
    if not allowed_token_uses:
        allowed_token_uses = ["access"]

    # Determine allowed client IDs (audience for ID tokens, client_id for access tokens)
    allowed_client_ids: List[str] = []
    raw_clients = getattr(settings, "cognito_allowed_client_ids", "")
    if raw_clients:
        allowed_client_ids = [c.strip() for c in raw_clients.split(",") if c.strip()]

    try:
        # Get signing key from JWKS
        signing_key = _jwks_cache.get_signing_key(token, issuer_url)

        # Decode and verify — require RS256
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer_url,
            options={
                "require": ["exp", "iss", "token_use"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": False,  # We handle aud/client_id manually per token_use
            },
        )
    except jwt.ExpiredSignatureError:
        logger.warning("jwt_verification_failed", reason="token_expired")
        raise AppError(code="UNAUTHORIZED", message="Token has expired", status_code=401, details={})
    except jwt.InvalidIssuerError:
        logger.warning("jwt_verification_failed", reason="invalid_issuer")
        raise AppError(code="UNAUTHORIZED", message="Invalid token issuer", status_code=401, details={})
    except jwt.InvalidAlgorithmError:
        logger.warning("jwt_verification_failed", reason="invalid_algorithm")
        raise AppError(code="UNAUTHORIZED", message="Invalid token algorithm", status_code=401, details={})
    except jwt.PyJWKClientError:
        logger.warning("jwt_verification_failed", reason="jwks_fetch_error")
        raise AppError(code="UNAUTHORIZED", message="Unable to verify token signature", status_code=401, details={})
    except jwt.InvalidTokenError as e:
        logger.warning("jwt_verification_failed", reason="invalid_token", error_type=type(e).__name__)
        raise AppError(code="UNAUTHORIZED", message="Invalid token", status_code=401, details={})
    except Exception:
        logger.warning("jwt_verification_failed", reason="unexpected_error")
        raise AppError(code="UNAUTHORIZED", message="Token verification failed", status_code=401, details={})

    # ── Validate token_use ──
    token_use = claims.get("token_use")
    if token_use not in allowed_token_uses:
        logger.warning(
            "jwt_verification_failed",
            reason="invalid_token_use",
            token_use=token_use,
            allowed=",".join(allowed_token_uses),
        )
        raise AppError(code="UNAUTHORIZED", message="Invalid token type", status_code=401, details={})

    # ── Validate client_id / aud per token type ──
    # In secure remote envs, COGNITO_ALLOWED_CLIENT_IDS must not be empty (defense-in-depth)
    env = getattr(settings, "env", "dev")
    from .config import _LOCAL_TEST_ENVS
    is_secure_remote = (env or "").lower().strip() not in _LOCAL_TEST_ENVS
    if is_secure_remote and not allowed_client_ids:
        logger.error("auth_config_error", reason="empty_allowed_client_ids_in_prod")
        raise AppError(
            code="INTERNAL_ERROR",
            message="Authentication service misconfigured",
            status_code=500,
            details={},
        )

    if allowed_client_ids:
        if token_use == "access":
            client_id = claims.get("client_id")
            if client_id not in allowed_client_ids:
                logger.warning("jwt_verification_failed", reason="invalid_client_id")
                raise AppError(code="UNAUTHORIZED", message="Token client not authorized", status_code=401, details={})
            # If aud exists on access token, validate it too
            aud = claims.get("aud")
            if aud is not None:
                aud_list = aud if isinstance(aud, list) else [aud]
                if not any(a in allowed_client_ids for a in aud_list):
                    logger.warning("jwt_verification_failed", reason="invalid_audience")
                    raise AppError(code="UNAUTHORIZED", message="Token audience not authorized", status_code=401, details={})
        elif token_use == "id":
            aud = claims.get("aud")
            if aud not in allowed_client_ids:
                logger.warning("jwt_verification_failed", reason="invalid_id_token_audience")
                raise AppError(code="UNAUTHORIZED", message="ID token audience not authorized", status_code=401, details={})

    return claims


# ── Tenant Resolution ──────────────────────────────────────

def _resolve_tenant_from_claims(claims: Dict[str, Any], settings: Any) -> Optional[str]:
    """Extract tenant from the configured claim name. Returns None if absent."""
    claim_name = settings.tenant_claim_name
    return claims.get(claim_name)


def _resolve_m2m_tenant(claims: Dict[str, Any], settings: Any) -> str:
    """Resolve tenant for M2M (client_credentials) tokens via explicit mapping.

    Raises AppError(403) if mapping is disabled, client_id is not mapped, or
    the resolved tenant fails validation.
    """
    m2m_mode = getattr(settings, "m2m_tenant_resolution", "disabled")

    if m2m_mode == "disabled":
        logger.warning(
            "m2m_tenant_resolution_failed",
            reason="m2m_resolution_disabled",
        )
        raise AppError(
            code="FORBIDDEN",
            message="M2M tokens require tenant claim or explicit client mapping",
            status_code=403,
            details={},
        )

    if m2m_mode != "client_id_map":
        logger.warning(
            "m2m_tenant_resolution_failed",
            reason="unsupported_m2m_mode",
            mode=m2m_mode,
        )
        raise AppError(
            code="FORBIDDEN",
            message="Unsupported M2M tenant resolution mode",
            status_code=403,
            details={},
        )

    # client_id_map mode
    client_id = claims.get("client_id")
    if not client_id:
        logger.warning("m2m_tenant_resolution_failed", reason="missing_client_id")
        raise AppError(
            code="FORBIDDEN",
            message="M2M token missing client_id",
            status_code=403,
            details={},
        )

    tenant_map = getattr(settings, "m2m_client_tenant_map", None) or {}

    if client_id not in tenant_map:
        logger.warning(
            "m2m_tenant_resolution_failed",
            reason="unmapped_client_id",
            # Log only first 8 chars of client_id for debugging without full exposure
            client_id_prefix=client_id[:8] if len(client_id) >= 8 else "***",
        )
        raise AppError(
            code="FORBIDDEN",
            message="M2M client not authorized for any tenant",
            status_code=403,
            details={},
        )

    mapped_tenant = tenant_map[client_id]
    return _validate_tenant_id(mapped_tenant, source="m2m_client_map")


# ── Auth Context Resolvers ────────────────────────────────

def _resolve_cognito_auth(
    token: str,
    settings: Any,
    legacy_tenant_header: Optional[str],
    request_path: str,
) -> AuthContext:
    """Full Cognito JWT verification → AuthContext."""
    claims = _verify_cognito_jwt(token, settings)

    subject = claims.get("sub")
    email = claims.get("email")
    name = claims.get("name") or claims.get("given_name")
    scopes_raw = claims.get("scope", "")
    scopes = scopes_raw.split() if isinstance(scopes_raw, str) else []
    token_use = claims.get("token_use", "access")

    # ── Log if legacy X-Tenant-Id is present (always ignore it) ──
    if legacy_tenant_header:
        logger.info(
            "legacy_tenant_header_ignored",
            path=request_path,
        )

    # ── Extract tenant from claims ──
    tenant_id = _resolve_tenant_from_claims(claims, settings)

    if tenant_id:
        tenant_id = _validate_tenant_id(tenant_id, source="jwt_claim")

        # P0-002: Validate deployment customer binding AFTER verified JWT
        _validate_deployment_customer(tenant_id, settings)

        logger.info(
            "auth_context_resolved",
            source="cognito_jwt",
            token_use=token_use,
            path=request_path,
        )
        return AuthContext(
            tenant_id=tenant_id,
            subject=subject,
            scopes=scopes,
            email=email,
            name=name,
            auth_source="cognito_jwt",
        )

    # ── No tenant claim: check if M2M token ──
    if token_use == "access" and claims.get("client_id") and not claims.get("cognito:username"):
        # Likely a client_credentials (M2M) token
        tenant_id = _resolve_m2m_tenant(claims, settings)
        logger.info(
            "auth_context_resolved",
            source="m2m_client_map",
            token_use=token_use,
            path=request_path,
        )
        return AuthContext(
            tenant_id=tenant_id,
            subject=subject or claims.get("client_id"),
            scopes=scopes,
            email=None,
            name=None,
            auth_source="m2m_client_map",
        )

    # ── User token without tenant claim → fail closed ──
    logger.warning(
        "tenant_resolution_failed",
        reason="missing_tenant_claim",
        claim_name=settings.tenant_claim_name,
        token_use=token_use,
        path=request_path,
    )
    raise AppError(
        code="FORBIDDEN",
        message="Token does not contain a tenant identifier",
        status_code=403,
        details={},
    )


def _validate_deployment_customer(
    token_customer_id: str,
    settings: Any,
) -> None:
    """P0-002: Validate that verified JWT customer matches deployment customer.

    In non-local deployments, SCANALYZE_DEPLOYMENT_CUSTOMER_ID is required
    (enforced at startup). A mismatch → 403.

    In local/test/ci without SCANALYZE_DEPLOYMENT_CUSTOMER_ID set, skip.

    IMPORTANT: This function must ONLY be called AFTER the JWT has been
    cryptographically verified against JWKS. Never call with unverified claims.
    """
    expected = getattr(settings, "scanalyze_deployment_customer_id", None)
    if not expected or not expected.strip():
        # Only possible in local/test/ci (startup validation enforces it elsewhere)
        return

    expected = expected.strip()
    if token_customer_id != expected:
        logger.warning(
            "deployment_customer_mismatch",
            expected_present=True,
            token_customer_present=bool(token_customer_id),
        )
        raise AppError(
            code="FORBIDDEN",
            message="Token customer is not authorized for this deployment",
            status_code=403,
            details={},
        )


def _resolve_local_mock_auth(settings: Any) -> AuthContext:
    """Local/test/ci mock auth. Only allowed when AUTH_MODE=local_mock AND APP_ENV∈{local,test,ci}.

    Legacy name LOCAL_MOCK_TENANT_ID retained for compatibility.
    Semantics are customer_id, not tenant header.
    LOCAL_MOCK_TENANT_ID is local/test/ci-only and never read in customer deployments.
    """
    env = (settings.env or "").lower().strip()
    safe_envs = {"local", "test", "ci"}

    if env not in safe_envs:
        raise RuntimeError(
            f"AUTH_MODE=local_mock is FORBIDDEN in APP_ENV='{settings.env}'. "
            f"Only allowed in: {safe_envs}"
        )

    mock_tenant = getattr(settings, "local_mock_tenant_id", None)
    if not mock_tenant:
        raise RuntimeError(
            "AUTH_MODE=local_mock requires LOCAL_MOCK_TENANT_ID to be set explicitly. "
            "Implicit 'default' tenant is not allowed."
        )

    tenant_id = _validate_tenant_id(mock_tenant, source="local_mock")
    mock_subject = getattr(settings, "local_mock_subject", "local-dev-user")

    logger.info(
        "auth_context_resolved",
        source="local_mock",
        env=env,
    )
    return AuthContext(
        tenant_id=tenant_id,
        subject=mock_subject,
        scopes=["scanalyze-ingest/ingest.read", "scanalyze-ingest/ingest.write"],
        email=None,
        name="Local Dev User",
        auth_source="local_mock",
    )


# ── FastAPI Dependency ─────────────────────────────────────

def get_auth_context(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"),
) -> AuthContext:
    """FastAPI dependency: resolve verified AuthContext for protected routes.

    Priority:
      1. If AUTH_MODE=local_mock and APP_ENV is safe → mock auth
      2. If AUTH_MODE=cognito_jwt → verify JWT against JWKS

    Security invariants:
      - X-Tenant-Id is NEVER used as tenant source. Presence is logged.
      - Fallback to "default" is NEVER applied.
      - JWT without signature verification is NEVER accepted.
      - If no trusted tenant can be resolved → 401 or 403.
    """
    settings = get_settings()
    auth_mode = getattr(settings, "auth_mode", "cognito_jwt")

    # ── Local mock mode ──
    if auth_mode == "local_mock":
        return _resolve_local_mock_auth(settings)

    # ── Cognito JWT mode (default) ──
    if not authorization:
        if x_tenant_id:
            logger.warning(
                "legacy_tenant_header_ignored",
                reason="no_authorization_header",
                path=str(request.url.path),
            )
        raise AppError(
            code="UNAUTHORIZED",
            message="Missing Authorization header",
            status_code=401,
            details={},
        )

    if not authorization.lower().startswith("bearer "):
        raise AppError(
            code="UNAUTHORIZED",
            message="Authorization header must use Bearer scheme",
            status_code=401,
            details={},
        )

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise AppError(
            code="UNAUTHORIZED",
            message="Empty bearer token",
            status_code=401,
            details={},
        )

    # Validate required Cognito config
    if not settings.cognito_user_pool_id:
        logger.error("auth_config_error", reason="missing_cognito_user_pool_id")
        raise AppError(
            code="INTERNAL_ERROR",
            message="Authentication service misconfigured",
            status_code=500,
            details={},
        )

    return _resolve_cognito_auth(
        token=token,
        settings=settings,
        legacy_tenant_header=x_tenant_id,
        request_path=str(request.url.path),
    )
