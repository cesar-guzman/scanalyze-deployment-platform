"""Explicit route authorization policies for versioned M2M principals."""
from __future__ import annotations

from collections.abc import Callable
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, FrozenSet

from fastapi import Depends, Request

from .auth import AuthContext, get_auth_context
from .enterprise_authorization import (
    EnterpriseAuthorizationRuntime,
    OperationId,
    authorize_operation,
    operation_policy,
)
from .errors import AppError
from .logging import get_logger


logger = get_logger()
ROUTE_ACTION_POLICY_ATTRIBUTE = "__scanalyze_required_actions__"
ROUTE_OPERATION_POLICY_ATTRIBUTE = "__scanalyze_operation_policy__"
OWNERSHIP_SCHEMA_VERSION = 1

_CUSTOMER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")
_DEPLOYMENT_ID_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
_KNOWN_PRINCIPAL_TYPES = frozenset({"user", "m2m", "local_mock"})


class ObjectAction(str, Enum):
    READ = "read"
    WRITE = "write"
    EXPORT = "export"


@dataclass(frozen=True)
class ObjectOwnership:
    """Canonical immutable customer/deployment binding for stored objects."""

    customer_id: str
    deployment_id: str

    def __post_init__(self) -> None:
        if not _is_valid_customer_id(self.customer_id):
            raise ValueError("customer_id is invalid")
        if not _is_valid_deployment_id(self.deployment_id):
            raise ValueError("deployment_id is invalid")

    @classmethod
    def from_auth(cls, auth: AuthContext) -> "ObjectOwnership":
        if auth is None or getattr(auth, "principal_type", None) not in _KNOWN_PRINCIPAL_TYPES:
            _deny_invalid_principal()
        try:
            return cls(
                customer_id=auth.customer_id,
                deployment_id=auth.deployment_id,  # type: ignore[arg-type]
            )
        except (AttributeError, TypeError, ValueError):
            _deny_invalid_principal()

    @property
    def partition(self) -> str:
        return f"CUSTOMER#{self.customer_id}#DEPLOYMENT#{self.deployment_id}"

    def batch_partition(self, batch_id: str) -> str:
        if not isinstance(batch_id, str) or not batch_id.strip() or "#" in batch_id:
            raise ValueError("batch_id is invalid")
        return f"{self.partition}#BATCH#{batch_id}"

    def document_prefix(self, document_id: str) -> str:
        if not isinstance(document_id, str) or not document_id.strip() or "#" in document_id:
            raise ValueError("document_id is invalid")
        return (
            f"customers/{self.customer_id}/deployments/{self.deployment_id}/"
            f"documents/{document_id}/"
        )

    def record_fields(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "deployment_id": self.deployment_id,
            "ownership_schema_version": OWNERSHIP_SCHEMA_VERSION,
            "ownership_key": self.partition,
        }


def _is_valid_customer_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_CUSTOMER_ID_PATTERN.fullmatch(value))


def _is_valid_deployment_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_DEPLOYMENT_ID_PATTERN.fullmatch(value))


def _deny_invalid_principal() -> None:
    logger.warning("object_authorization_failed", reason="invalid_auth_context")
    raise AppError(
        code="FORBIDDEN",
        message="Principal is not authorized for this operation",
        status_code=403,
        details={},
    )


def _hidden_object(kind: str, reason: str) -> None:
    logger.warning(
        "object_authorization_failed",
        reason=reason,
        object_type=kind.lower(),
    )
    raise AppError(
        code="NOT_FOUND",
        message=f"{kind} not found",
        status_code=404,
        details={},
    )


def _required_actions(action: ObjectAction) -> FrozenSet[str]:
    if action is ObjectAction.READ:
        return frozenset({"read"})
    if action is ObjectAction.WRITE:
        return frozenset({"write"})
    if action is ObjectAction.EXPORT:
        return frozenset({"read", "admin"})
    _deny_invalid_principal()


def _coerce_action(action: ObjectAction | str) -> ObjectAction:
    try:
        return action if isinstance(action, ObjectAction) else ObjectAction(action)
    except (TypeError, ValueError):
        _deny_invalid_principal()


def _record_ownership(record: Mapping[str, Any], kind: str) -> ObjectOwnership:
    if record.get("ownership_schema_version") != OWNERSHIP_SCHEMA_VERSION:
        _hidden_object(kind, "unsupported_ownership_schema")

    customer_id = record.get("customer_id")
    deployment_id = record.get("deployment_id")
    try:
        ownership = ObjectOwnership(
            customer_id=customer_id,  # type: ignore[arg-type]
            deployment_id=deployment_id,  # type: ignore[arg-type]
        )
    except (TypeError, ValueError):
        _hidden_object(kind, "invalid_ownership")

    for alias in ("tenantId", "tenant_id", "customerId"):
        if alias in record and record.get(alias) != ownership.customer_id:
            _hidden_object(kind, "conflicting_customer_ownership")
    if "deploymentId" in record and record.get("deploymentId") != ownership.deployment_id:
        _hidden_object(kind, "conflicting_deployment_ownership")

    expected_partition = ownership.partition
    if "ownership_key" in record and record.get("ownership_key") != expected_partition:
        _hidden_object(kind, "conflicting_ownership_partition")
    return ownership


def authorize_owned_record(
    auth: AuthContext,
    record: Mapping[str, Any] | None,
    required_action: ObjectAction | str,
    *,
    object_kind: str,
) -> ObjectOwnership:
    """Authorize one canonical record without revealing foreign-object existence."""

    expected = ObjectOwnership.from_auth(auth)
    action = _coerce_action(required_action)
    _authorize_m2m_actions(auth, _required_actions(action))
    if not isinstance(record, Mapping):
        _hidden_object(object_kind, "missing_object")
    actual = _record_ownership(record, object_kind)
    if actual != expected:
        _hidden_object(object_kind, "ownership_mismatch")
    return actual


def authorize_document(
    auth: AuthContext,
    document_record: Mapping[str, Any] | None,
    required_action: ObjectAction | str,
) -> ObjectOwnership:
    return authorize_owned_record(
        auth,
        document_record,
        required_action,
        object_kind="Document",
    )


def authorize_batch(
    auth: AuthContext,
    batch_record: Mapping[str, Any] | None,
    required_action: ObjectAction | str,
) -> ObjectOwnership:
    return authorize_owned_record(
        auth,
        batch_record,
        required_action,
        object_kind="Batch",
    )


def authorize_batch_membership(
    auth: AuthContext,
    batch_record: Mapping[str, Any] | None,
    document_records: Sequence[Mapping[str, Any]],
    required_action: ObjectAction | str,
) -> ObjectOwnership:
    """Authorize a batch and every member; a single invalid member denies all."""

    ownership = authorize_batch(auth, batch_record, required_action)
    batch_id = batch_record.get("batchId") if isinstance(batch_record, Mapping) else None
    if not isinstance(batch_id, str) or not batch_id:
        _hidden_object("Batch", "invalid_batch_identifier")

    for record in document_records:
        try:
            authorize_document(auth, record, required_action)
        except AppError:
            _hidden_object("Batch", "invalid_batch_member_ownership")
        if record.get("batchId") != batch_id:
            _hidden_object("Batch", "invalid_batch_membership")
    return ownership


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
    if auth.principal_type != "m2m":
        _deny_invalid_principal()
    return _authorize_m2m_actions(auth, frozenset({"read"}))


def require_write_access(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if auth.principal_type != "m2m":
        _deny_invalid_principal()
    return _authorize_m2m_actions(auth, frozenset({"write"}))


def require_export_access(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    if auth.principal_type != "m2m":
        _deny_invalid_principal()
    return _authorize_m2m_actions(auth, frozenset({"read", "admin"}))


def require_operation(
    operation_id: OperationId,
) -> Callable[..., AuthContext]:
    """Create one closed PEP dependency for a reviewed operation identifier."""
    policy = operation_policy(operation_id)

    def dependency(
        request: Request,
        auth: AuthContext = Depends(get_auth_context),
    ) -> AuthContext:
        runtime = getattr(
            request.app.state,
            "enterprise_authorization_runtime",
            None,
        )
        if runtime is not None and not isinstance(
            runtime,
            EnterpriseAuthorizationRuntime,
        ):
            runtime = None
        return authorize_operation(
            auth,
            policy.operation_id,
            runtime=runtime,
        )

    dependency.__name__ = f"require_{operation_id.value.replace('.', '_')}"
    setattr(dependency, ROUTE_OPERATION_POLICY_ATTRIBUTE, policy.operation_id)
    return _mark_policy(dependency, policy.m2m_required_actions)


_mark_policy(require_read_access, frozenset({"read"}))
_mark_policy(require_write_access, frozenset({"write"}))
_mark_policy(require_export_access, frozenset({"read", "admin"}))
