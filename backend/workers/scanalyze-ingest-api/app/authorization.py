"""Explicit route authorization policies for versioned M2M principals."""
from __future__ import annotations

from collections.abc import Callable
from typing import FrozenSet

from fastapi import Depends

from .auth import AuthContext, get_auth_context
from .errors import AppError
from .logging import get_logger


logger = get_logger()
ROUTE_ACTION_POLICY_ATTRIBUTE = "__scanalyze_required_actions__"


def _authorize_m2m_actions(
    auth: AuthContext,
    required_actions: FrozenSet[str],
) -> AuthContext:
    """Enforce logical actions for M2M while preserving user/local behavior."""
    if auth.principal_type != "m2m":
        return auth
    if not required_actions.issubset(auth.granted_actions):
        logger.warning(
            "m2m_route_authorization_failed",
            reason="missing_required_action",
            required_action_count=len(required_actions),
            granted_action_count=len(auth.granted_actions),
        )
        raise AppError(
            code="FORBIDDEN",
            message="M2M principal is not authorized for this operation",
            status_code=403,
            details={},
        )
    return auth


def _mark_policy(
    dependency: Callable[..., AuthContext],
    required_actions: FrozenSet[str],
) -> Callable[..., AuthContext]:
    setattr(dependency, ROUTE_ACTION_POLICY_ATTRIBUTE, required_actions)
    return dependency


def require_read_access(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    return _authorize_m2m_actions(auth, frozenset({"read"}))


def require_write_access(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    return _authorize_m2m_actions(auth, frozenset({"write"}))


def require_export_access(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    return _authorize_m2m_actions(auth, frozenset({"read", "admin"}))


_mark_policy(require_read_access, frozenset({"read"}))
_mark_policy(require_write_access, frozenset({"write"}))
_mark_policy(require_export_access, frozenset({"read", "admin"}))
