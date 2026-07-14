"""Portable, recoverable, fail-closed enterprise user lifecycle orchestration.

The module contains no provider or persistence SDK calls.  A reviewed runtime
installs explicit ports for conditional operations, ownership-bound membership
queries, provider reconciliation, approval resolution, session revocation, and
append-only audit.  HTTP input never supplies customer or deployment authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth import AuthContext
from .enterprise_authorization import (
    ASSURANCE_SOURCE,
    ASSURANCE_VERSION,
    AUTHZ_SCHEMA_VERSION,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
    Assurance,
    AssuranceSource,
    AssuranceVersion,
    AuthorizationPath,
    HumanAuthorizationSnapshot,
    HumanRole,
)
from .errors import AppError


MEMBERSHIP_SCHEMA_VERSION = "enterprise-membership.v1"
LIFECYCLE_APPROVAL_SCHEMA_VERSION = "lifecycle-approval-evidence.v1"
LIFECYCLE_OPERATION_SCHEMA_VERSION = "lifecycle-operation.v1"
LIFECYCLE_AUDIT_EVENT_SCHEMA_VERSION = "lifecycle-audit-event.v1"
LIFECYCLE_AUDIT_RECEIPT_SCHEMA_VERSION = "lifecycle-audit-receipt.v1"
MAX_INVITATION_TTL_SECONDS = 86_400
MAX_PRIVILEGED_AUTH_AGE_SECONDS = 300

_CUSTOMER_PATTERN = re.compile(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
_DEPLOYMENT_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
_SUBJECT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$")
_REFERENCE_PATTERN = re.compile(r"^ref_[0-9a-f]{24,64}$")
_MEMBERSHIP_REFERENCE_PATTERN = re.compile(r"^mbr_[0-9a-f]{32,64}$")
_APPROVAL_REFERENCE_PATTERN = re.compile(r"^apr_[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^idem_[A-Za-z0-9][A-Za-z0-9_-]{15,63}$")
_REASON_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_CURSOR_PATTERN = re.compile(r"^cur_[A-Za-z0-9_-]{16,256}$")
_LOCATOR_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_IDENTITY_AUTHORITY_FIELDS = frozenset(
    {"customerid", "deploymentid", "tenantid", "xtenantid"}
)


class MembershipState(str, Enum):
    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"


class LifecycleOperation(str, Enum):
    INVITE = "membership.invite"
    ACTIVATE = "membership.activate"
    CHANGE_ROLE = "membership.change_role"
    SUSPEND = "membership.suspend"
    REACTIVATE = "membership.reactivate"
    REVOKE = "membership.revoke"
    REVOKE_SESSIONS = "membership.revoke_sessions"


class LifecycleOperationStage(str, Enum):
    RESERVED = "reserved"
    APPROVAL_VALIDATED = "approval_validated"
    PROVIDER_APPLIED = "provider_applied"
    MEMBERSHIP_APPLIED = "membership_applied"
    SESSIONS_REVOKED = "sessions_revoked"
    AUDIT_COMMITTED = "audit_committed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class MembershipRecord:
    schema_version: str
    membership_reference: str
    subject: str
    customer_id: str
    deployment_id: str
    state: MembershipState
    role_id: HumanRole
    membership_version: int
    provider_user_reference: str
    provider_principal_key: str
    created_at: datetime
    updated_at: datetime
    invitation_expires_at: datetime | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "membershipReference": self.membership_reference,
            "state": self.state.value,
            "roleId": self.role_id.value,
            "membershipVersion": str(self.membership_version),
            "createdAt": _timestamp(self.created_at),
            "updatedAt": _timestamp(self.updated_at),
            "invitationExpiresAt": (
                _timestamp(self.invitation_expires_at)
                if self.invitation_expires_at is not None
                else None
            ),
        }


@dataclass(frozen=True)
class MembershipPage:
    items: tuple[MembershipRecord, ...]
    next_cursor: str | None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_public_dict() for item in self.items],
            "nextCursor": self.next_cursor,
        }


@dataclass(frozen=True)
class LifecycleCommand:
    operation: LifecycleOperation
    customer_id: str
    deployment_id: str
    actor_subject: str
    idempotency_key: str
    request_digest: str


@dataclass(frozen=True)
class LifecycleOperationRecord:
    schema_version: str
    operation_reference: str
    operation: LifecycleOperation
    customer_id: str
    deployment_id: str
    actor_subject: str
    idempotency_key: str
    request_digest: str
    stage: LifecycleOperationStage
    evidence: Mapping[str, str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def new(
        cls,
        command: LifecycleCommand,
        *,
        now: datetime,
    ) -> "LifecycleOperationRecord":
        reference = "op_" + hashlib.sha256(
            "\x1f".join(
                (
                    command.customer_id,
                    command.deployment_id,
                    command.idempotency_key,
                )
            ).encode("utf-8")
        ).hexdigest()[:32]
        return cls(
            schema_version=LIFECYCLE_OPERATION_SCHEMA_VERSION,
            operation_reference=reference,
            operation=command.operation,
            customer_id=command.customer_id,
            deployment_id=command.deployment_id,
            actor_subject=command.actor_subject,
            idempotency_key=command.idempotency_key,
            request_digest=command.request_digest,
            stage=LifecycleOperationStage.RESERVED,
            evidence={},
            created_at=now,
            updated_at=now,
        )


@dataclass(frozen=True)
class ApprovalEvidence:
    schema_version: str
    approval_reference: str
    approver_subject: str
    customer_id: str
    deployment_id: str
    operation: LifecycleOperation
    target_reference: str
    request_digest: str
    state: str
    expires_at: datetime


@dataclass(frozen=True)
class ProviderUserReceipt:
    subject: str
    provider_user_reference: str
    provider_principal_key: str
    principal_locator_digest: str
    state: str


@dataclass(frozen=True)
class LifecycleAuditReceipt:
    schema_version: str
    decision_id: str
    receipt_reference: str
    acknowledged_at: datetime


@dataclass(frozen=True)
class LifecycleOutcome:
    status: str
    operation_reference: str

    def to_public_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "operationReference": self.operation_reference,
        }


@dataclass(frozen=True)
class LifecycleAuditEvent:
    event_reference: str
    timestamp: datetime
    action: LifecycleOperation
    decision: str
    reason_code: str
    principal_reference: str
    correlation_reference: str
    before_membership_version: str
    after_membership_version: str

    def to_public_dict(self) -> dict[str, str]:
        return {
            "eventReference": self.event_reference,
            "timestamp": _timestamp(self.timestamp),
            "action": self.action.value,
            "decision": self.decision,
            "reasonCode": self.reason_code,
            "principalReference": self.principal_reference,
            "correlationReference": self.correlation_reference,
            "beforeMembershipVersion": self.before_membership_version,
            "afterMembershipVersion": self.after_membership_version,
        }


@dataclass(frozen=True)
class LifecycleAuditPage:
    items: tuple[LifecycleAuditEvent, ...]
    next_cursor: str | None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_public_dict() for item in self.items],
            "nextCursor": self.next_cursor,
        }


class IdempotencyConflict(RuntimeError):
    """A key was already bound to a different canonical command."""


class LifecycleOperationStore(Protocol):
    def reserve_operation(self, command: LifecycleCommand) -> LifecycleOperationRecord: ...

    def checkpoint_operation(
        self,
        record: LifecycleOperationRecord,
        *,
        expected_stage: LifecycleOperationStage,
        next_stage: LifecycleOperationStage,
        evidence: dict[str, str] | None = None,
    ) -> LifecycleOperationRecord: ...


class MembershipStore(Protocol):
    def list_memberships(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        state: MembershipState | None,
        cursor: str | None,
        limit: int,
    ) -> MembershipPage: ...

    def load_membership(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        membership_reference: str,
    ) -> MembershipRecord | None: ...

    def create_invited_membership(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        provider_receipt: ProviderUserReceipt,
        role_id: HumanRole,
        expires_at: datetime,
        operation_reference: str,
    ) -> MembershipRecord: ...

    def transition_membership(
        self,
        *,
        current: MembershipRecord,
        expected_state: MembershipState,
        expected_version: int,
        next_state: MembershipState,
        next_role: HumanRole,
        operation_reference: str,
        admin_replacement: MembershipRecord | None,
    ) -> MembershipRecord: ...


class IdentityLifecycleProvider(Protocol):
    def invite_user(self, **request: Any) -> ProviderUserReceipt: ...
    def confirm_activation(self, **request: Any) -> ProviderUserReceipt: ...
    def set_user_enabled(self, **request: Any) -> ProviderUserReceipt: ...
    def revoke_sessions(self, **request: Any) -> str: ...


class ApprovalResolver(Protocol):
    def resolve(self, **request: Any) -> ApprovalEvidence: ...


class LifecycleAuditSink(Protocol):
    def emit(self, event: dict[str, Any]) -> LifecycleAuditReceipt: ...


class LifecycleAuditReader(Protocol):
    def list_events(
        self,
        *,
        customer_id: str,
        deployment_id: str,
        cursor: str | None,
        limit: int,
    ) -> LifecycleAuditPage: ...


@dataclass(frozen=True)
class EnterpriseLifecycleRuntime:
    operation_store: LifecycleOperationStore
    membership_store: MembershipStore
    identity_provider: IdentityLifecycleProvider
    approval_resolver: ApprovalResolver
    audit_sink: LifecycleAuditSink
    clock: Callable[[], datetime]
    audit_reader: LifecycleAuditReader | None = None


class _IdentitySafeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_identity_authority(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            normalized = {
                key.replace("_", "").replace("-", "").lower()
                for key in value
                if isinstance(key, str)
            }
            if normalized.intersection(_IDENTITY_AUTHORITY_FIELDS):
                raise ValueError("request payload cannot establish identity authority")
        return value


class UserInvitationRequest(_IdentitySafeModel):
    principal_locator: str = Field(min_length=3, max_length=320)
    role_id: HumanRole
    expires_in_seconds: int = Field(ge=60, le=MAX_INVITATION_TTL_SECONDS)
    approval_reference: str

    @field_validator("principal_locator")
    @classmethod
    def _validate_locator(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _LOCATOR_PATTERN.fullmatch(normalized):
            raise ValueError("principal locator is invalid")
        return normalized

    @field_validator("approval_reference")
    @classmethod
    def _validate_approval(cls, value: str) -> str:
        if not _APPROVAL_REFERENCE_PATTERN.fullmatch(value):
            raise ValueError("approval reference is invalid")
        return value


class TransitionRequest(_IdentitySafeModel):
    expected_membership_version: int = Field(ge=1)
    approval_reference: str
    reason_code: str
    replacement_membership_reference: str | None = None

    @field_validator("approval_reference")
    @classmethod
    def _validate_approval(cls, value: str) -> str:
        if not _APPROVAL_REFERENCE_PATTERN.fullmatch(value):
            raise ValueError("approval reference is invalid")
        return value

    @field_validator("reason_code")
    @classmethod
    def _validate_reason(cls, value: str) -> str:
        if not _REASON_PATTERN.fullmatch(value):
            raise ValueError("reason code is invalid")
        return value

    @field_validator("replacement_membership_reference")
    @classmethod
    def _validate_replacement(cls, value: str | None) -> str | None:
        if value is not None and not _MEMBERSHIP_REFERENCE_PATTERN.fullmatch(value):
            raise ValueError("replacement membership reference is invalid")
        return value


class RoleChangeRequest(TransitionRequest):
    role_id: HumanRole


_ALLOWED_TRANSITIONS: Mapping[LifecycleOperation, tuple[MembershipState, MembershipState]] = {
    LifecycleOperation.ACTIVATE: (MembershipState.INVITED, MembershipState.ACTIVE),
    LifecycleOperation.SUSPEND: (MembershipState.ACTIVE, MembershipState.SUSPENDED),
    LifecycleOperation.REACTIVATE: (MembershipState.SUSPENDED, MembershipState.ACTIVE),
    LifecycleOperation.REVOKE: (MembershipState.ACTIVE, MembershipState.REVOKED),
}


class UserLifecycleService:
    """Recoverable orchestration over provider-neutral conditional ports."""

    def __init__(self, runtime: EnterpriseLifecycleRuntime) -> None:
        self.runtime = runtime

    def role_catalog(self, auth: AuthContext) -> tuple[str, ...]:
        self._require_admin(auth, privileged=False)
        return tuple(role.value for role in HumanRole)

    def list_memberships(
        self,
        auth: AuthContext,
        *,
        state: MembershipState | None,
        cursor: str | None,
        limit: int,
    ) -> MembershipPage:
        owner = self._require_admin(auth, privileged=False)
        if cursor is not None and not _CURSOR_PATTERN.fullmatch(cursor):
            _invalid_request()
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            _invalid_request()
        try:
            page = self.runtime.membership_store.list_memberships(
                customer_id=owner[0],
                deployment_id=owner[1],
                state=state,
                cursor=cursor,
                limit=limit,
            )
        except Exception:
            _unavailable()
        if not isinstance(page, MembershipPage):
            _unavailable()
        if page.next_cursor is not None and not _CURSOR_PATTERN.fullmatch(page.next_cursor):
            _unavailable()
        for item in page.items:
            self._validate_membership(item, owner=owner)
        return page

    def list_audit_events(
        self,
        auth: AuthContext,
        *,
        cursor: str | None,
        limit: int,
    ) -> LifecycleAuditPage:
        owner = self._require_lifecycle_reader(auth)
        if cursor is not None and not _CURSOR_PATTERN.fullmatch(cursor):
            _invalid_request()
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            _invalid_request()
        reader = self.runtime.audit_reader
        if reader is None:
            _unavailable()
        try:
            page = reader.list_events(
                customer_id=owner[0],
                deployment_id=owner[1],
                cursor=cursor,
                limit=limit,
            )
        except Exception:
            _unavailable()
        if not isinstance(page, LifecycleAuditPage):
            _unavailable()
        if page.next_cursor is not None and not _CURSOR_PATTERN.fullmatch(page.next_cursor):
            _unavailable()
        for event in page.items:
            if not (
                isinstance(event, LifecycleAuditEvent)
                and _REFERENCE_PATTERN.fullmatch(event.event_reference)
                and _aware(event.timestamp)
                and isinstance(event.action, LifecycleOperation)
                and event.decision in {"allow", "deny"}
                and _REASON_PATTERN.fullmatch(event.reason_code)
                and _REFERENCE_PATTERN.fullmatch(event.principal_reference)
                and _REFERENCE_PATTERN.fullmatch(event.correlation_reference)
                and event.before_membership_version.isdigit()
                and event.after_membership_version.isdigit()
            ):
                _unavailable()
        return page

    def invite_user(
        self,
        auth: AuthContext,
        request: UserInvitationRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        owner = self._require_admin(auth, privileged=True)
        actor = str(auth.subject)
        target_digest = _digest(request.principal_locator)
        command = self._command(
            LifecycleOperation.INVITE,
            auth,
            idempotency_key,
            {
                "principal_locator": request.principal_locator,
                "role_id": request.role_id.value,
                "expires_in_seconds": request.expires_in_seconds,
                "approval_reference": request.approval_reference,
            },
        )
        record = self._reserve(command)
        if record.stage is LifecycleOperationStage.COMPLETED:
            return LifecycleOutcome("completed", record.operation_reference)

        if record.stage is LifecycleOperationStage.RESERVED:
            approval = self._resolve_approval(
                request.approval_reference,
                operation=command.operation,
                target_reference=target_digest,
                request_digest=record.request_digest,
                actor_subject=actor,
                target_subject=None,
                owner=owner,
            )
            record = self._checkpoint(
                record,
                expected=LifecycleOperationStage.RESERVED,
                next_stage=LifecycleOperationStage.APPROVAL_VALIDATED,
                evidence={
                    "approval_reference": approval.approval_reference,
                    "target_reference": target_digest,
                    "role_id": request.role_id.value,
                    "expires_at": _timestamp(
                        self._now() + timedelta(seconds=request.expires_in_seconds)
                    ),
                },
            )

        if record.stage is LifecycleOperationStage.APPROVAL_VALIDATED:
            try:
                provider = self.runtime.identity_provider.invite_user(
                    principal_locator=request.principal_locator,
                    principal_locator_digest=target_digest,
                    customer_id=owner[0],
                    deployment_id=owner[1],
                    idempotency_key=idempotency_key,
                )
            except Exception:
                _unavailable()
            self._validate_provider_receipt(
                provider,
                expected_locator_digest=target_digest,
                expected_state="invited",
            )
            record = self._checkpoint(
                record,
                expected=LifecycleOperationStage.APPROVAL_VALIDATED,
                next_stage=LifecycleOperationStage.PROVIDER_APPLIED,
                evidence={
                    "subject": provider.subject,
                    "provider_user_reference": provider.provider_user_reference,
                    "provider_principal_key": provider.provider_principal_key,
                    "principal_locator_digest": provider.principal_locator_digest,
                },
            )

        if record.stage is LifecycleOperationStage.PROVIDER_APPLIED:
            provider = ProviderUserReceipt(
                subject=record.evidence["subject"],
                provider_user_reference=record.evidence["provider_user_reference"],
                provider_principal_key=record.evidence["provider_principal_key"],
                principal_locator_digest=record.evidence["principal_locator_digest"],
                state="invited",
            )
            expires_at = _parse_timestamp(record.evidence.get("expires_at"))
            if expires_at is None:
                _unavailable()
            try:
                membership = self.runtime.membership_store.create_invited_membership(
                    customer_id=owner[0],
                    deployment_id=owner[1],
                    provider_receipt=provider,
                    role_id=HumanRole(record.evidence["role_id"]),
                    expires_at=expires_at,
                    operation_reference=record.operation_reference,
                )
            except Exception:
                _unavailable()
            self._validate_membership(membership, owner=owner)
            if membership.state is not MembershipState.INVITED:
                _unavailable()
            record = self._checkpoint(
                record,
                expected=LifecycleOperationStage.PROVIDER_APPLIED,
                next_stage=LifecycleOperationStage.MEMBERSHIP_APPLIED,
                evidence={
                    "membership_reference": membership.membership_reference,
                    "before_membership_version": "0",
                    "after_membership_version": str(membership.membership_version),
                    "reason_code": "invitation_created",
                },
            )

        return self._audit_and_complete(record, auth)

    def activate_membership(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.ACTIVATE,
            idempotency_key=idempotency_key,
        )

    def suspend_membership(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.SUSPEND,
            idempotency_key=idempotency_key,
        )

    def reactivate_membership(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.REACTIVATE,
            idempotency_key=idempotency_key,
        )

    def revoke_membership(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.REVOKE,
            idempotency_key=idempotency_key,
        )

    def change_role(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: RoleChangeRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.CHANGE_ROLE,
            idempotency_key=idempotency_key,
            next_role=request.role_id,
        )

    def revoke_sessions(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        idempotency_key: str,
    ) -> LifecycleOutcome:
        return self._transition(
            auth,
            membership_reference,
            request,
            operation=LifecycleOperation.REVOKE_SESSIONS,
            idempotency_key=idempotency_key,
        )

    def _transition(
        self,
        auth: AuthContext,
        membership_reference: str,
        request: TransitionRequest,
        *,
        operation: LifecycleOperation,
        idempotency_key: str,
        next_role: HumanRole | None = None,
    ) -> LifecycleOutcome:
        owner = self._require_admin(auth, privileged=True)
        if not _MEMBERSHIP_REFERENCE_PATTERN.fullmatch(membership_reference):
            _not_found()
        command = self._command(
            operation,
            auth,
            idempotency_key,
            {
                "membership_reference": membership_reference,
                "expected_membership_version": request.expected_membership_version,
                "approval_reference": request.approval_reference,
                "reason_code": request.reason_code,
                "replacement_membership_reference": request.replacement_membership_reference,
                "next_role": next_role.value if next_role is not None else None,
            },
        )
        record = self._reserve(command)
        if record.stage is LifecycleOperationStage.COMPLETED:
            return LifecycleOutcome("completed", record.operation_reference)

        if record.stage is LifecycleOperationStage.RESERVED:
            member = self._load_owned(owner, membership_reference)
            if member.subject == auth.subject:
                _deny()
            if member.membership_version != request.expected_membership_version:
                _conflict()
            if operation is LifecycleOperation.CHANGE_ROLE:
                expected_state = MembershipState.ACTIVE
                desired_state = MembershipState.ACTIVE
                desired_role = next_role
                if desired_role is None or desired_role is member.role_id:
                    _conflict()
            elif operation is LifecycleOperation.REVOKE_SESSIONS:
                expected_state = member.state
                desired_state = member.state
                desired_role = member.role_id
                if member.state not in {MembershipState.ACTIVE, MembershipState.SUSPENDED}:
                    _conflict()
            else:
                expected_state, desired_state = _ALLOWED_TRANSITIONS[operation]
                desired_role = member.role_id
                if member.state is not expected_state:
                    _conflict()
            if operation is LifecycleOperation.ACTIVATE and not (
                _aware(member.invitation_expires_at)
                and member.invitation_expires_at > self._now()
            ):
                _conflict()
            admin_replacement = self._require_last_admin_safe(
                owner,
                member,
                desired_state=desired_state,
                desired_role=desired_role,
                replacement_reference=request.replacement_membership_reference,
            )
            approval = self._resolve_approval(
                request.approval_reference,
                operation=operation,
                target_reference=member.membership_reference,
                request_digest=record.request_digest,
                actor_subject=str(auth.subject),
                target_subject=member.subject,
                owner=owner,
            )
            checkpoint_evidence = {
                "approval_reference": approval.approval_reference,
                "membership_reference": member.membership_reference,
                "subject": member.subject,
                "provider_user_reference": member.provider_user_reference,
                "provider_principal_key": member.provider_principal_key,
                "expected_state": expected_state.value,
                "desired_state": desired_state.value,
                "before_role_id": member.role_id.value,
                "after_role_id": desired_role.value,
                "before_membership_version": str(member.membership_version),
                "reason_code": request.reason_code,
                "effect_order": (
                    "provider_before_membership"
                    if operation in {
                        LifecycleOperation.ACTIVATE,
                        LifecycleOperation.REACTIVATE,
                    }
                    else "membership_before_provider"
                    if operation in {
                        LifecycleOperation.SUSPEND,
                        LifecycleOperation.REVOKE,
                    }
                    else "membership_only"
                ),
            }
            if admin_replacement is not None:
                checkpoint_evidence.update(
                    {
                        "admin_replacement_reference": (
                            admin_replacement.membership_reference
                        ),
                        "admin_replacement_version": str(
                            admin_replacement.membership_version
                        ),
                    }
                )
            record = self._checkpoint(
                record,
                expected=LifecycleOperationStage.RESERVED,
                next_stage=LifecycleOperationStage.APPROVAL_VALIDATED,
                evidence=checkpoint_evidence,
            )

        provider_before_membership = operation in {
            LifecycleOperation.ACTIVATE,
            LifecycleOperation.REACTIVATE,
        }
        provider_after_membership = operation in {
            LifecycleOperation.SUSPEND,
            LifecycleOperation.REVOKE,
        }
        expected_effect_order = (
            "provider_before_membership"
            if provider_before_membership
            else "membership_before_provider"
            if provider_after_membership
            else "membership_only"
        )
        if record.stage is not LifecycleOperationStage.RESERVED and (
            record.evidence.get("effect_order") != expected_effect_order
        ):
            _unavailable()

        if record.stage is LifecycleOperationStage.APPROVAL_VALIDATED:
            if provider_before_membership:
                record = self._apply_provider_effect(
                    record,
                    operation=operation,
                    owner=owner,
                    idempotency_key=idempotency_key,
                    expected_stage=LifecycleOperationStage.APPROVAL_VALIDATED,
                )
            else:
                record = self._apply_membership_effect(
                    record,
                    owner=owner,
                    expected_stage=LifecycleOperationStage.APPROVAL_VALIDATED,
                )

        if (
            provider_before_membership
            and record.stage is LifecycleOperationStage.PROVIDER_APPLIED
        ):
            record = self._apply_membership_effect(
                record,
                owner=owner,
                expected_stage=LifecycleOperationStage.PROVIDER_APPLIED,
            )

        if (
            provider_after_membership
            and record.stage is LifecycleOperationStage.MEMBERSHIP_APPLIED
        ):
            record = self._apply_provider_effect(
                record,
                operation=operation,
                owner=owner,
                idempotency_key=idempotency_key,
                expected_stage=LifecycleOperationStage.MEMBERSHIP_APPLIED,
            )

        needs_session_revoke = operation is not LifecycleOperation.ACTIVATE
        session_ready_stage = (
            LifecycleOperationStage.PROVIDER_APPLIED
            if provider_after_membership
            else LifecycleOperationStage.MEMBERSHIP_APPLIED
        )
        if record.stage is session_ready_stage and needs_session_revoke:
            try:
                revocation_reference = self.runtime.identity_provider.revoke_sessions(
                    subject=record.evidence["subject"],
                    provider_user_reference=record.evidence["provider_user_reference"],
                    provider_principal_key=record.evidence["provider_principal_key"],
                    customer_id=owner[0],
                    deployment_id=owner[1],
                    idempotency_key=idempotency_key,
                )
            except Exception:
                _unavailable()
            if not isinstance(revocation_reference, str) or not _REFERENCE_PATTERN.fullmatch(
                revocation_reference
            ):
                _unavailable()
            record = self._checkpoint(
                record,
                expected=session_ready_stage,
                next_stage=LifecycleOperationStage.SESSIONS_REVOKED,
                evidence={"session_revocation_reference": revocation_reference},
            )

        return self._audit_and_complete(record, auth)

    def _apply_provider_effect(
        self,
        record: LifecycleOperationRecord,
        *,
        operation: LifecycleOperation,
        owner: tuple[str, str],
        idempotency_key: str,
        expected_stage: LifecycleOperationStage,
    ) -> LifecycleOperationRecord:
        if operation is LifecycleOperation.ACTIVATE:
            provider_call = self.runtime.identity_provider.confirm_activation
            provider_args: dict[str, Any] = {}
        elif operation in {
            LifecycleOperation.SUSPEND,
            LifecycleOperation.REVOKE,
            LifecycleOperation.REACTIVATE,
        }:
            provider_call = self.runtime.identity_provider.set_user_enabled
            provider_args = {"enabled": operation is LifecycleOperation.REACTIVATE}
        else:
            _unavailable()
        try:
            receipt = provider_call(
                subject=record.evidence["subject"],
                provider_user_reference=record.evidence["provider_user_reference"],
                provider_principal_key=record.evidence["provider_principal_key"],
                customer_id=owner[0],
                deployment_id=owner[1],
                idempotency_key=idempotency_key,
                **provider_args,
            )
        except Exception:
            _unavailable()
        expected_provider_state = (
            "active"
            if operation in {
                LifecycleOperation.ACTIVATE,
                LifecycleOperation.REACTIVATE,
            }
            else "disabled"
        )
        self._validate_provider_receipt(
            receipt,
            expected_subject=record.evidence["subject"],
            expected_provider_reference=record.evidence["provider_user_reference"],
            expected_state=expected_provider_state,
        )
        return self._checkpoint(
            record,
            expected=expected_stage,
            next_stage=LifecycleOperationStage.PROVIDER_APPLIED,
        )

    def _apply_membership_effect(
        self,
        record: LifecycleOperationRecord,
        *,
        owner: tuple[str, str],
        expected_stage: LifecycleOperationStage,
    ) -> LifecycleOperationRecord:
        current = self._load_owned(owner, record.evidence["membership_reference"])
        before_version = int(record.evidence["before_membership_version"])
        after_state = MembershipState(record.evidence["desired_state"])
        after_role = HumanRole(record.evidence["after_role_id"])
        if (
            current.membership_version == before_version + 1
            and current.state is after_state
            and current.role_id is after_role
        ):
            updated = current
        else:
            admin_replacement = None
            replacement_reference = record.evidence.get(
                "admin_replacement_reference", ""
            )
            if replacement_reference:
                admin_replacement = self._load_owned(owner, replacement_reference)
                if not (
                    admin_replacement.state is MembershipState.ACTIVE
                    and admin_replacement.role_id is HumanRole.CUSTOMER_ADMIN
                    and str(admin_replacement.membership_version)
                    == record.evidence.get("admin_replacement_version")
                ):
                    _conflict()
            try:
                updated = self.runtime.membership_store.transition_membership(
                    current=current,
                    expected_state=MembershipState(record.evidence["expected_state"]),
                    expected_version=before_version,
                    next_state=after_state,
                    next_role=after_role,
                    operation_reference=record.operation_reference,
                    admin_replacement=admin_replacement,
                )
            except Exception:
                _conflict()
        self._validate_membership(updated, owner=owner)
        return self._checkpoint(
            record,
            expected=expected_stage,
            next_stage=LifecycleOperationStage.MEMBERSHIP_APPLIED,
            evidence={"after_membership_version": str(updated.membership_version)},
        )

    def _audit_and_complete(
        self,
        record: LifecycleOperationRecord,
        auth: AuthContext,
    ) -> LifecycleOutcome:
        audit_ready = {
            LifecycleOperationStage.MEMBERSHIP_APPLIED,
            LifecycleOperationStage.SESSIONS_REVOKED,
        }
        if record.stage in audit_ready:
            event = self._audit_event(record, auth)
            try:
                receipt = self.runtime.audit_sink.emit(event)
            except Exception:
                _unavailable()
            if not (
                isinstance(receipt, LifecycleAuditReceipt)
                and receipt.schema_version == LIFECYCLE_AUDIT_RECEIPT_SCHEMA_VERSION
                and hmac.compare_digest(receipt.decision_id, event["decision_id"])
                and _REFERENCE_PATTERN.fullmatch(receipt.receipt_reference)
                and _aware(receipt.acknowledged_at)
                and receipt.acknowledged_at <= self._now()
            ):
                _unavailable()
            record = self._checkpoint(
                record,
                expected=record.stage,
                next_stage=LifecycleOperationStage.AUDIT_COMMITTED,
                evidence={"audit_receipt_reference": receipt.receipt_reference},
            )
        if record.stage is LifecycleOperationStage.AUDIT_COMMITTED:
            record = self._checkpoint(
                record,
                expected=LifecycleOperationStage.AUDIT_COMMITTED,
                next_stage=LifecycleOperationStage.COMPLETED,
            )
        if record.stage is not LifecycleOperationStage.COMPLETED:
            _unavailable()
        return LifecycleOutcome("completed", record.operation_reference)

    def _audit_event(
        self,
        record: LifecycleOperationRecord,
        auth: AuthContext,
    ) -> dict[str, Any]:
        decision_id = _reference(
            record.operation_reference,
            record.operation.value,
            record.request_digest,
        )
        snapshot = auth.human_authorization
        return {
            "event_schema_version": LIFECYCLE_AUDIT_EVENT_SCHEMA_VERSION,
            "timestamp": _timestamp(record.created_at),
            "decision_id": decision_id,
            "principal_type": "user",
            "principal_reference": _reference(record.actor_subject),
            "customer_reference": _reference(record.customer_id),
            "deployment_reference": _reference(record.deployment_id),
            "action": record.operation.value,
            "resource_type": "authorization_administration",
            "decision": "allow",
            "reason_code": record.evidence.get("reason_code", "approved_lifecycle_change"),
            "policy_version": POLICY_VERSION,
            "policy_digest": POLICY_DIGEST,
            "assurance": getattr(snapshot, "assurance", None).value,
            "correlation_reference": _reference(record.operation_reference),
            "approval_references": [record.evidence["approval_reference"]],
            "before_membership_version": record.evidence.get(
                "before_membership_version", "0"
            ),
            "after_membership_version": record.evidence["after_membership_version"],
        }

    def _command(
        self,
        operation: LifecycleOperation,
        auth: AuthContext,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> LifecycleCommand:
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(
            idempotency_key
        ):
            _invalid_request()
        canonical = json.dumps(
            {
                "operation": operation.value,
                "payload": payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return LifecycleCommand(
            operation=operation,
            customer_id=auth.customer_id,
            deployment_id=str(auth.deployment_id),
            actor_subject=str(auth.subject),
            idempotency_key=idempotency_key,
            request_digest=_digest(canonical),
        )

    def _reserve(self, command: LifecycleCommand) -> LifecycleOperationRecord:
        try:
            record = self.runtime.operation_store.reserve_operation(command)
        except IdempotencyConflict:
            _conflict()
        except Exception:
            _unavailable()
        if not (
            isinstance(record, LifecycleOperationRecord)
            and record.schema_version == LIFECYCLE_OPERATION_SCHEMA_VERSION
            and record.operation is command.operation
            and record.customer_id == command.customer_id
            and record.deployment_id == command.deployment_id
            and record.actor_subject == command.actor_subject
            and record.idempotency_key == command.idempotency_key
            and hmac.compare_digest(record.request_digest, command.request_digest)
        ):
            _conflict()
        return record

    def _checkpoint(
        self,
        record: LifecycleOperationRecord,
        *,
        expected: LifecycleOperationStage,
        next_stage: LifecycleOperationStage,
        evidence: dict[str, str] | None = None,
    ) -> LifecycleOperationRecord:
        try:
            updated = self.runtime.operation_store.checkpoint_operation(
                record,
                expected_stage=expected,
                next_stage=next_stage,
                evidence=evidence,
            )
        except Exception:
            _unavailable()
        if not isinstance(updated, LifecycleOperationRecord):
            _unavailable()
        return updated

    def _load_owned(
        self,
        owner: tuple[str, str],
        membership_reference: str,
    ) -> MembershipRecord:
        try:
            result = self.runtime.membership_store.load_membership(
                customer_id=owner[0],
                deployment_id=owner[1],
                membership_reference=membership_reference,
            )
        except Exception:
            _unavailable()
        if result is None:
            _not_found()
        self._validate_membership(result, owner=owner)
        return result

    def _validate_membership(
        self,
        member: MembershipRecord,
        *,
        owner: tuple[str, str],
    ) -> None:
        if not (
            isinstance(member, MembershipRecord)
            and member.schema_version == MEMBERSHIP_SCHEMA_VERSION
            and _MEMBERSHIP_REFERENCE_PATTERN.fullmatch(member.membership_reference)
            and _SUBJECT_PATTERN.fullmatch(member.subject)
            and member.customer_id == owner[0]
            and member.deployment_id == owner[1]
            and isinstance(member.state, MembershipState)
            and isinstance(member.role_id, HumanRole)
            and isinstance(member.membership_version, int)
            and not isinstance(member.membership_version, bool)
            and member.membership_version >= 1
            and _REFERENCE_PATTERN.fullmatch(member.provider_user_reference)
            and _SUBJECT_PATTERN.fullmatch(member.provider_principal_key)
            and _aware(member.created_at)
            and _aware(member.updated_at)
            and (
                (
                    member.state is MembershipState.INVITED
                    and _aware(member.invitation_expires_at)
                )
                or (
                    member.state is not MembershipState.INVITED
                    and member.invitation_expires_at is None
                )
            )
        ):
            _unavailable()

    def _validate_provider_receipt(
        self,
        receipt: ProviderUserReceipt,
        *,
        expected_state: str,
        expected_locator_digest: str | None = None,
        expected_subject: str | None = None,
        expected_provider_reference: str | None = None,
    ) -> None:
        if not (
            isinstance(receipt, ProviderUserReceipt)
            and _SUBJECT_PATTERN.fullmatch(receipt.subject)
            and _REFERENCE_PATTERN.fullmatch(receipt.provider_user_reference)
            and _SUBJECT_PATTERN.fullmatch(receipt.provider_principal_key)
            and _DIGEST_PATTERN.fullmatch(receipt.principal_locator_digest)
            and receipt.state == expected_state
            and (
                expected_locator_digest is None
                or hmac.compare_digest(
                    receipt.principal_locator_digest, expected_locator_digest
                )
            )
            and (expected_subject is None or receipt.subject == expected_subject)
            and (
                expected_provider_reference is None
                or receipt.provider_user_reference == expected_provider_reference
            )
        ):
            _unavailable()

    def _resolve_approval(
        self,
        approval_reference: str,
        *,
        operation: LifecycleOperation,
        target_reference: str,
        request_digest: str,
        actor_subject: str,
        target_subject: str | None,
        owner: tuple[str, str],
    ) -> ApprovalEvidence:
        try:
            evidence = self.runtime.approval_resolver.resolve(
                approval_reference=approval_reference,
                operation=operation,
                target_reference=target_reference,
                request_digest=request_digest,
                customer_id=owner[0],
                deployment_id=owner[1],
                now=self._now(),
            )
        except Exception:
            _deny()
        if not (
            isinstance(evidence, ApprovalEvidence)
            and evidence.schema_version == LIFECYCLE_APPROVAL_SCHEMA_VERSION
            and evidence.approval_reference == approval_reference
            and _SUBJECT_PATTERN.fullmatch(evidence.approver_subject)
            and evidence.customer_id == owner[0]
            and evidence.deployment_id == owner[1]
            and evidence.operation is operation
            and hmac.compare_digest(evidence.target_reference, target_reference)
            and hmac.compare_digest(evidence.request_digest, request_digest)
            and evidence.state == "approved"
            and _aware(evidence.expires_at)
            and evidence.expires_at > self._now()
            and evidence.approver_subject != actor_subject
            and (
                target_subject is None
                or evidence.approver_subject != target_subject
            )
        ):
            _deny()
        return evidence

    def _require_last_admin_safe(
        self,
        owner: tuple[str, str],
        member: MembershipRecord,
        *,
        desired_state: MembershipState,
        desired_role: HumanRole,
        replacement_reference: str | None,
    ) -> MembershipRecord | None:
        removes_admin = (
            member.state is MembershipState.ACTIVE
            and member.role_id is HumanRole.CUSTOMER_ADMIN
            and (
                desired_state is not MembershipState.ACTIVE
                or desired_role is not HumanRole.CUSTOMER_ADMIN
            )
        )
        if not removes_admin:
            return None
        if replacement_reference is None:
            _conflict()
        replacement = self._load_owned(owner, replacement_reference)
        if not (
            replacement.membership_reference != member.membership_reference
            and replacement.state is MembershipState.ACTIVE
            and replacement.role_id is HumanRole.CUSTOMER_ADMIN
        ):
            _conflict()
        return replacement

    def _require_admin(
        self,
        auth: AuthContext,
        *,
        privileged: bool,
    ) -> tuple[str, str]:
        return self._require_roles(
            auth,
            roles=frozenset({HumanRole.CUSTOMER_ADMIN}),
            privileged=privileged,
        )

    def _require_roles(
        self,
        auth: AuthContext,
        *,
        roles: frozenset[HumanRole],
        privileged: bool,
    ) -> tuple[str, str]:
        now = self._now()
        if not (
            isinstance(auth, AuthContext)
            and auth.principal_type == "user"
            and auth.auth_source == "cognito_jwt"
            and isinstance(auth.customer_id, str)
            and _CUSTOMER_PATTERN.fullmatch(auth.customer_id)
            and isinstance(auth.deployment_id, str)
            and _DEPLOYMENT_PATTERN.fullmatch(auth.deployment_id)
            and isinstance(auth.subject, str)
            and _SUBJECT_PATTERN.fullmatch(auth.subject)
            and isinstance(auth.human_authorization, HumanAuthorizationSnapshot)
        ):
            _deny()
        snapshot = auth.human_authorization
        if not (
            snapshot.authorization_path is AuthorizationPath.MEMBERSHIP
            and snapshot.subject == auth.subject
            and snapshot.customer_id == auth.customer_id
            and snapshot.deployment_id == auth.deployment_id
            and snapshot.membership_state == "active"
            and snapshot.role_id in roles
            and snapshot.authz_schema_version == AUTHZ_SCHEMA_VERSION
            and snapshot.scope_catalog_version == SCOPE_CATALOG_VERSION
            and snapshot.role_catalog_version == ROLE_CATALOG_VERSION
            and snapshot.policy_version == POLICY_VERSION
            and isinstance(snapshot.policy_digest, str)
            and hmac.compare_digest(snapshot.policy_digest, POLICY_DIGEST)
        ):
            _deny()
        if privileged:
            authenticated_at = snapshot.authenticated_at_epoch
            if not (
                snapshot.assurance is Assurance.PHISHING_RESISTANT_MFA
                and snapshot.assurance_source
                is AssuranceSource.AUTHORITATIVE_AUTHENTICATION_EVENT
                and snapshot.assurance_version
                is AssuranceVersion.PHISHING_RESISTANT_MFA_V1
                and snapshot.authentication_event_reference is not None
                and _REFERENCE_PATTERN.fullmatch(
                    snapshot.authentication_event_reference
                )
                and isinstance(authenticated_at, int)
                and not isinstance(authenticated_at, bool)
                and 0 <= int(now.timestamp()) - authenticated_at
                <= MAX_PRIVILEGED_AUTH_AGE_SECONDS
            ):
                _deny()
        return auth.customer_id, auth.deployment_id

    def _require_lifecycle_reader(self, auth: AuthContext) -> tuple[str, str]:
        return self._require_roles(
            auth,
            roles=frozenset({HumanRole.CUSTOMER_ADMIN, HumanRole.AUDITOR}),
            privileged=False,
        )

    def _now(self) -> datetime:
        try:
            value = self.runtime.clock()
        except Exception:
            _unavailable()
        if not _aware(value):
            _unavailable()
        return value.astimezone(timezone.utc)


def _aware(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if _aware(result) else None


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reference(*values: object) -> str:
    material = "\x1f".join(str(value) for value in values)
    return "ref_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _deny() -> None:
    raise AppError(
        code="FORBIDDEN",
        message="Lifecycle operation is not authorized",
        status_code=403,
        details={},
    )


def _not_found() -> None:
    raise AppError(
        code="NOT_FOUND",
        message="Membership was not found",
        status_code=404,
        details={},
    )


def _conflict() -> None:
    raise AppError(
        code="CONFLICT",
        message="Lifecycle operation could not be applied",
        status_code=409,
        details={},
    )


def _invalid_request() -> None:
    raise AppError(
        code="INVALID_REQUEST",
        message="Lifecycle request is invalid",
        status_code=400,
        details={},
    )


def _unavailable() -> None:
    raise AppError(
        code="SERVICE_UNAVAILABLE",
        message="Lifecycle service is unavailable",
        status_code=503,
        details={},
    )
