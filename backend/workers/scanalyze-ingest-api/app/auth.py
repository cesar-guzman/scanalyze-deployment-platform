"""Customer-aware authentication context for Scanalyze Ingest API.

P0-001: Customer identity derived from verified auth — never from client-supplied headers.

Design decisions:
- JWT signature verified cryptographically against Cognito JWKS (RS256).
- Customer identity extracted exclusively from verified JWT claims (e.g. custom:customerId).
- X-Tenant-Id header is rejected in protected routes and is never an identity source.
- Fallback to "default" customer is PROHIBITED in protected routes.
- M2M tokens use a versioned server-side client binding that includes customer,
  deployment, and required scopes.
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
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, FrozenSet, Iterable, List, Literal, Optional

import jwt  # PyJWT
from fastapi import Header, Request

from .config import get_settings
from .errors import AppError
from .logging import get_logger

# ── Constants ──────────────────────────────────────────────

_TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{0,126}[a-zA-Z0-9]$")
_CUSTOMER_ULID_PATTERN = re.compile(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
_DEPLOYMENT_ULID_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
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

@dataclass(frozen=True, init=False)
class AuthContext:
    """Verified authentication context for a request.

    NOTE: tenant_id is a LEGACY field name. Semantically it carries the
    SaaS customer_id (e.g. customer-example), NOT a document processing route
    (platform/personal/gov/bank). Resource routing is determined by
    SCANALYZE_TENANT env var, not this field.
    See ADR: 05_ADR_Modelo_SaaS_Multi_Account.
    """
    customer_id: str
    deployment_id: Optional[str]
    principal_type: Literal["user", "m2m", "local_mock"]
    subject: Optional[str]
    client_id: Optional[str]
    scopes: FrozenSet[str]
    granted_actions: FrozenSet[str]
    email: Optional[str]
    name: Optional[str]
    auth_source: str

    def __init__(
        self,
        customer_id: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
        deployment_id: Optional[str] = None,
        principal_type: Optional[Literal["user", "m2m", "local_mock"]] = None,
        subject: Optional[str] = None,
        client_id: Optional[str] = None,
        scopes: Iterable[str] = (),
        granted_actions: Iterable[str] = (),
        email: Optional[str] = None,
        name: Optional[str] = None,
        auth_source: str = "cognito_jwt",
    ) -> None:
        """Build a typed context while retaining the legacy tenant_id keyword."""
        if customer_id and tenant_id and customer_id != tenant_id:
            raise ValueError("customer_id and tenant_id aliases must match")
        resolved_customer = customer_id or tenant_id
        if not resolved_customer:
            raise ValueError("customer_id is required")

        resolved_principal_type = principal_type
        if resolved_principal_type is None:
            if auth_source == "local_mock":
                resolved_principal_type = "local_mock"
            elif auth_source in {"m2m_client_map", "m2m_identity_binding_v1"}:
                resolved_principal_type = "m2m"
            else:
                resolved_principal_type = "user"

        object.__setattr__(self, "customer_id", resolved_customer)
        object.__setattr__(self, "deployment_id", deployment_id)
        object.__setattr__(self, "principal_type", resolved_principal_type)
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "scopes", frozenset(scopes))
        object.__setattr__(self, "granted_actions", frozenset(granted_actions))
        object.__setattr__(self, "email", email)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "auth_source", auth_source)

    @property
    def tenant_id(self) -> str:
        """Deprecated read-only alias for customer_id."""
        return self.customer_id

    # Backwards-compatible alias used by all existing route handlers
    @property
    def tenant(self) -> str:
        return self.customer_id


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


def _validate_m2m_customer_id(customer_id: Any) -> str:
    if not isinstance(customer_id, str) or not _CUSTOMER_ULID_PATTERN.fullmatch(customer_id):
        logger.warning("m2m_identity_binding_failed", reason="invalid_customer_id")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )
    return customer_id


def _validate_m2m_deployment_id(deployment_id: Any) -> str:
    if not isinstance(deployment_id, str) or not _DEPLOYMENT_ULID_PATTERN.fullmatch(deployment_id):
        logger.warning("m2m_identity_binding_failed", reason="invalid_deployment_id")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )
    return deployment_id


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


def _is_human_principal(claims: Dict[str, Any]) -> bool:
    """Recognize both Cognito access-token username claim representations."""
    return bool(claims.get("cognito:username") or claims.get("username"))


def _binding_value(binding: Any, field_name: str) -> Any:
    if isinstance(binding, dict):
        return binding.get(field_name)
    return getattr(binding, field_name, None)


def _derive_m2m_granted_actions(
    binding_scopes: FrozenSet[str],
    settings: Any,
) -> FrozenSet[str]:
    """Derive logical actions exclusively from the versioned binding policy."""
    policy = getattr(settings, "m2m_action_scope_sets_v1", None)
    if policy is None:
        logger.warning("m2m_identity_binding_failed", reason="missing_action_scope_policy")
        raise AppError(
            code="FORBIDDEN",
            message="M2M authorization policy is not configured",
            status_code=403,
            details={},
        )

    action_sets: dict[str, FrozenSet[str]] = {}
    for action in ("read", "write", "admin"):
        raw_scopes = _binding_value(policy, action)
        if not isinstance(raw_scopes, (list, tuple, set, frozenset)):
            logger.warning("m2m_identity_binding_failed", reason="invalid_action_scope_policy")
            raise AppError(
                code="FORBIDDEN",
                message="M2M authorization policy is invalid",
                status_code=403,
                details={},
            )
        scopes = frozenset(
            scope.strip()
            for scope in raw_scopes
            if isinstance(scope, str) and scope.strip()
        )
        if not scopes or len(scopes) != len(raw_scopes):
            logger.warning("m2m_identity_binding_failed", reason="invalid_action_scope_policy")
            raise AppError(
                code="FORBIDDEN",
                message="M2M authorization policy is invalid",
                status_code=403,
                details={},
            )
        action_sets[action] = scopes

    if any(
        action_sets[left].intersection(action_sets[right])
        for left, right in (("read", "write"), ("read", "admin"), ("write", "admin"))
    ):
        logger.warning("m2m_identity_binding_failed", reason="overlapping_action_scope_policy")
        raise AppError(
            code="FORBIDDEN",
            message="M2M authorization policy is invalid",
            status_code=403,
            details={},
        )

    policy_scope_union = frozenset().union(*action_sets.values())
    if not binding_scopes.issubset(policy_scope_union):
        logger.warning("m2m_identity_binding_failed", reason="binding_scope_outside_policy")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )

    granted_actions: set[str] = set()
    for action, action_scopes in action_sets.items():
        overlap = binding_scopes.intersection(action_scopes)
        if overlap and overlap != action_scopes:
            logger.warning("m2m_identity_binding_failed", reason="partial_action_scope_set")
            raise AppError(
                code="FORBIDDEN",
                message="M2M identity binding is invalid",
                status_code=403,
                details={},
            )
        if action_scopes.issubset(binding_scopes):
            granted_actions.add(action)

    if not granted_actions:
        logger.warning("m2m_identity_binding_failed", reason="binding_grants_no_actions")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )
    return frozenset(granted_actions)


def _resolve_m2m_identity(
    claims: Dict[str, Any],
    settings: Any,
    scopes: FrozenSet[str],
) -> AuthContext:
    """Resolve and validate the complete versioned M2M identity tuple."""
    mode_value = getattr(settings, "m2m_tenant_resolution", "disabled")
    mode = mode_value.strip().lower() if isinstance(mode_value, str) else "disabled"
    if mode != "client_identity_bindings_v1":
        reason = "legacy_client_id_map_forbidden" if mode == "client_id_map" else "m2m_resolution_disabled"
        logger.warning("m2m_identity_binding_failed", reason=reason)
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is not configured",
            status_code=403,
            details={},
        )

    client_id = claims.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        logger.warning("m2m_identity_binding_failed", reason="missing_client_id")
        raise AppError(
            code="FORBIDDEN",
            message="M2M client is not authorized",
            status_code=403,
            details={},
        )

    if claims.get("token_use") != "access":
        logger.warning("m2m_identity_binding_failed", reason="invalid_token_use")
        raise AppError(
            code="UNAUTHORIZED",
            message="Invalid token type",
            status_code=401,
            details={},
        )

    bindings = getattr(settings, "m2m_client_identity_bindings_v1", None) or {}
    if not isinstance(bindings, dict) or client_id not in bindings:
        logger.warning("m2m_identity_binding_failed", reason="unmapped_client_id")
        raise AppError(
            code="FORBIDDEN",
            message="M2M client is not authorized",
            status_code=403,
            details={},
        )

    binding = bindings[client_id]
    mapped_customer = _validate_m2m_customer_id(_binding_value(binding, "customer_id"))
    mapped_deployment = _validate_m2m_deployment_id(_binding_value(binding, "deployment_id"))
    if mapped_customer == mapped_deployment:
        logger.warning("m2m_identity_binding_failed", reason="identities_not_distinct")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )

    raw_required_scopes = _binding_value(binding, "required_scopes")
    if not isinstance(raw_required_scopes, (list, tuple, set, frozenset)):
        logger.warning("m2m_identity_binding_failed", reason="invalid_required_scopes")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )
    required_scopes = frozenset(
        scope.strip()
        for scope in raw_required_scopes
        if isinstance(scope, str) and scope.strip()
    )
    if not required_scopes or len(required_scopes) != len(raw_required_scopes):
        logger.warning("m2m_identity_binding_failed", reason="invalid_required_scopes")
        raise AppError(
            code="FORBIDDEN",
            message="M2M identity binding is invalid",
            status_code=403,
            details={},
        )
    granted_actions = _derive_m2m_granted_actions(required_scopes, settings)

    expected_customer = _validate_m2m_customer_id(
        getattr(settings, "scanalyze_deployment_customer_id", None)
    )
    expected_deployment = _validate_m2m_deployment_id(
        getattr(settings, "scanalyze_deployment_id", None)
    )
    if mapped_customer != expected_customer:
        logger.warning("m2m_identity_binding_failed", reason="customer_mismatch")
        raise AppError(
            code="FORBIDDEN",
            message="M2M client is not authorized for this deployment",
            status_code=403,
            details={},
        )
    if mapped_deployment != expected_deployment:
        logger.warning("m2m_identity_binding_failed", reason="deployment_mismatch")
        raise AppError(
            code="FORBIDDEN",
            message="M2M client is not authorized for this deployment",
            status_code=403,
            details={},
        )
    if not required_scopes.issubset(scopes):
        logger.warning("m2m_identity_binding_failed", reason="insufficient_scope")
        raise AppError(
            code="FORBIDDEN",
            message="M2M token has insufficient scope",
            status_code=403,
            details={},
        )

    customer_claim_name = getattr(settings, "tenant_claim_name", "custom:customerId")
    signed_customer = claims.get(customer_claim_name)
    if signed_customer is not None and signed_customer != mapped_customer:
        logger.warning("m2m_identity_binding_failed", reason="customer_claim_mismatch")
        raise AppError(
            code="FORBIDDEN",
            message="M2M token identity does not match its binding",
            status_code=403,
            details={},
        )

    deployment_claim_name = getattr(settings, "deployment_claim_name", "custom:deployment_id")
    signed_deployment = claims.get(deployment_claim_name)
    if signed_deployment is not None and signed_deployment != mapped_deployment:
        logger.warning("m2m_identity_binding_failed", reason="deployment_claim_mismatch")
        raise AppError(
            code="FORBIDDEN",
            message="M2M token identity does not match its binding",
            status_code=403,
            details={},
        )

    logger.info("auth_context_resolved", source="m2m_identity_binding_v1", token_use="access")
    return AuthContext(
        customer_id=mapped_customer,
        deployment_id=mapped_deployment,
        principal_type="m2m",
        subject=claims.get("sub") or client_id,
        client_id=client_id,
        scopes=scopes,
        granted_actions=granted_actions,
        email=None,
        name=None,
        auth_source="m2m_identity_binding_v1",
    )


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
    scopes = frozenset(scopes_raw.split()) if isinstance(scopes_raw, str) else frozenset()
    token_use = claims.get("token_use", "access")

    # Identity-bearing legacy headers are rejected, never used or silently ignored.
    if legacy_tenant_header is not None:
        logger.warning(
            "legacy_tenant_header_rejected",
            path=request_path,
        )
        raise AppError(
            code="FORBIDDEN",
            message="Client-supplied identity headers are not allowed",
            status_code=403,
            details={},
        )

    client_id = claims.get("client_id")
    is_machine_principal = bool(client_id) and not _is_human_principal(claims)
    if is_machine_principal:
        return _resolve_m2m_identity(claims, settings, scopes)

    if getattr(settings, "human_enterprise_authorization_enabled", None) is not True:
        logger.warning(
            "human_enterprise_authorization_denied",
            reason="runtime_disabled",
            path=request_path,
        )
        raise AppError(
            code="FORBIDDEN",
            message="Access is not available for this principal",
            status_code=403,
            details={},
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
        expected_deployment_value = getattr(settings, "scanalyze_deployment_id", None)
        expected_deployment = (
            expected_deployment_value
            if isinstance(expected_deployment_value, str)
            and _DEPLOYMENT_ULID_PATTERN.fullmatch(expected_deployment_value)
            else None
        )
        return AuthContext(
            customer_id=tenant_id,
            deployment_id=expected_deployment,
            principal_type="user",
            subject=subject,
            client_id=client_id,
            scopes=scopes,
            email=email,
            name=name,
            auth_source="cognito_jwt",
        )

    # ── No tenant claim: check if M2M token ──
    if token_use == "access" and claims.get("client_id") and not _is_human_principal(claims):
        return _resolve_m2m_identity(claims, settings, scopes)

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
    deployment_id = getattr(settings, "scanalyze_deployment_id", None)
    if (
        not isinstance(deployment_id, str)
        or not _DEPLOYMENT_ULID_PATTERN.fullmatch(deployment_id)
    ):
        raise RuntimeError(
            "AUTH_MODE=local_mock requires an explicit valid "
            "SCANALYZE_DEPLOYMENT_ID; no deployment default is inferred."
        )
    mock_subject = getattr(settings, "local_mock_subject", "local-dev-user")

    logger.info(
        "auth_context_resolved",
        source="local_mock",
        env=env,
    )
    return AuthContext(
        customer_id=tenant_id,
        deployment_id=deployment_id,
        principal_type="local_mock",
        subject=mock_subject,
        client_id=None,
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
      - X-Tenant-Id is rejected and is NEVER used as an identity source.
      - Fallback to "default" is NEVER applied.
      - JWT without signature verification is NEVER accepted.
      - If no trusted tenant can be resolved → 401 or 403.
    """
    settings = get_settings()
    auth_mode = getattr(settings, "auth_mode", "cognito_jwt")

    # ── Local mock mode ──
    if auth_mode == "local_mock":
        if x_tenant_id is not None:
            logger.warning(
                "legacy_tenant_header_rejected",
                path=str(request.url.path),
            )
            raise AppError(
                code="FORBIDDEN",
                message="Client-supplied identity headers are not allowed",
                status_code=403,
                details={},
            )
        return _resolve_local_mock_auth(settings)

    # ── Cognito JWT mode (default) ──
    if not authorization:
        if x_tenant_id:
            logger.warning(
                "legacy_tenant_header_rejected",
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
