"""Versioned enterprise user lifecycle administration API for GUG-94."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, ConfigDict

from ...auth import AuthContext
from ...authorization import require_operation
from ...enterprise_authorization import OperationId
from ...errors import AppError
from ...user_lifecycle import (
    EnterpriseLifecycleRuntime,
    MembershipState,
    RoleChangeRequest,
    TransitionRequest,
    UserInvitationRequest,
    UserLifecycleService,
)


router = APIRouter()

_READ_ROLES = require_operation(OperationId.AUTHORIZATION_ROLES_READ)
_LIST_MEMBERSHIPS = require_operation(OperationId.AUTHORIZATION_MEMBERSHIPS_LIST)
_CREATE_INVITATION = require_operation(OperationId.AUTHORIZATION_INVITATIONS_CREATE)
_ACTIVATE_MEMBERSHIP = require_operation(OperationId.AUTHORIZATION_MEMBERSHIPS_ACTIVATE)
_CHANGE_ROLE = require_operation(OperationId.AUTHORIZATION_MEMBERSHIPS_ROLE_CHANGE)
_SUSPEND_MEMBERSHIP = require_operation(OperationId.AUTHORIZATION_MEMBERSHIPS_SUSPEND)
_REACTIVATE_MEMBERSHIP = require_operation(
    OperationId.AUTHORIZATION_MEMBERSHIPS_REACTIVATE
)
_REVOKE_MEMBERSHIP = require_operation(OperationId.AUTHORIZATION_MEMBERSHIPS_REVOKE)
_REVOKE_SESSIONS = require_operation(OperationId.AUTHORIZATION_SESSIONS_REVOKE)
_READ_AUDIT = require_operation(OperationId.AUTHORIZATION_AUDIT_READ)


class RoleCatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schemaVersion: str = "enterprise-roles.v1"
    roles: tuple[str, ...]


class MembershipListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: list[dict[str, Any]]
    nextCursor: str | None = None


class LifecycleOutcomeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: str
    operationReference: str


class AuditEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    items: list[dict[str, Any]]
    nextCursor: str | None = None


def get_lifecycle_service(request: Request) -> UserLifecycleService:
    runtime = getattr(request.app.state, "enterprise_lifecycle_runtime", None)
    if not isinstance(runtime, EnterpriseLifecycleRuntime):
        raise AppError(
            code="SERVICE_UNAVAILABLE",
            message="Lifecycle service is unavailable",
            status_code=503,
            details={},
        )
    return UserLifecycleService(runtime)


IdempotencyKey = Annotated[str, Header(alias="Idempotency-Key")]
LifecycleService = Annotated[UserLifecycleService, Depends(get_lifecycle_service)]


@router.get("/roles", response_model=RoleCatalogResponse)
def read_role_catalog(
    auth: AuthContext = Depends(_READ_ROLES),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> RoleCatalogResponse:
    return RoleCatalogResponse(roles=service.role_catalog(auth))


@router.get("/memberships", response_model=MembershipListResponse)
def list_memberships(
    state: MembershipState | None = Query(default=None),
    cursor: str | None = Query(default=None, min_length=20, max_length=260),
    limit: int = Query(default=50, ge=1, le=100),
    auth: AuthContext = Depends(_LIST_MEMBERSHIPS),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> MembershipListResponse:
    return MembershipListResponse.model_validate(
        service.list_memberships(
            auth,
            state=state,
            cursor=cursor,
            limit=limit,
        ).to_public_dict()
    )


@router.post("/invitations", response_model=LifecycleOutcomeResponse)
def create_invitation(
    body: UserInvitationRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_CREATE_INVITATION),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return LifecycleOutcomeResponse.model_validate(
        service.invite_user(auth, body, idempotency_key=idempotency_key).to_public_dict()
    )


def _transition_response(outcome: Any) -> LifecycleOutcomeResponse:
    return LifecycleOutcomeResponse.model_validate(outcome.to_public_dict())


@router.post(
    "/memberships/{membership_reference}/activations",
    response_model=LifecycleOutcomeResponse,
)
def activate_membership(
    membership_reference: str,
    body: TransitionRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_ACTIVATE_MEMBERSHIP),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.activate_membership(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.post(
    "/memberships/{membership_reference}/role-changes",
    response_model=LifecycleOutcomeResponse,
)
def change_role(
    membership_reference: str,
    body: RoleChangeRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_CHANGE_ROLE),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.change_role(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.post(
    "/memberships/{membership_reference}/suspensions",
    response_model=LifecycleOutcomeResponse,
)
def suspend_membership(
    membership_reference: str,
    body: TransitionRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_SUSPEND_MEMBERSHIP),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.suspend_membership(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.post(
    "/memberships/{membership_reference}/reactivations",
    response_model=LifecycleOutcomeResponse,
)
def reactivate_membership(
    membership_reference: str,
    body: TransitionRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_REACTIVATE_MEMBERSHIP),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.reactivate_membership(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.post(
    "/memberships/{membership_reference}/revocations",
    response_model=LifecycleOutcomeResponse,
)
def revoke_membership(
    membership_reference: str,
    body: TransitionRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_REVOKE_MEMBERSHIP),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.revoke_membership(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.post(
    "/memberships/{membership_reference}/session-revocations",
    response_model=LifecycleOutcomeResponse,
)
def revoke_sessions(
    membership_reference: str,
    body: TransitionRequest,
    idempotency_key: IdempotencyKey,
    auth: AuthContext = Depends(_REVOKE_SESSIONS),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> LifecycleOutcomeResponse:
    return _transition_response(
        service.revoke_sessions(
            auth, membership_reference, body, idempotency_key=idempotency_key
        )
    )


@router.get("/audit-events", response_model=AuditEventListResponse)
def list_audit_events(
    cursor: str | None = Query(default=None, min_length=20, max_length=260),
    limit: int = Query(default=50, ge=1, le=100),
    auth: AuthContext = Depends(_READ_AUDIT),
    service: LifecycleService = None,  # type: ignore[assignment]
) -> AuditEventListResponse:
    return AuditEventListResponse.model_validate(
        service.list_audit_events(auth, cursor=cursor, limit=limit).to_public_dict()
    )
