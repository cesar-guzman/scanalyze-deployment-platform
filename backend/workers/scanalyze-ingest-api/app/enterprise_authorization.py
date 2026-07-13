"""Portable, fail-closed enterprise authorization for protected API operations.

The module is deliberately provider neutral.  Authentication adapters populate
``AuthContext.human_authorization`` only from validated internal evidence; HTTP
headers, path/query values, payload fields, groups, and display attributes never
participate in a policy decision.
"""
from __future__ import annotations

import hmac
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, FrozenSet, Mapping, TYPE_CHECKING

from .errors import AppError
from .logging import current_log_reference, get_logger, opaque_log_reference

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for static analysis
    from .auth import AuthContext


logger = get_logger()

AUTHORIZATION_CONTEXT_SCHEMA_VERSION = "human-authorization-context.v1"
AUTHZ_SCHEMA_VERSION = "enterprise-authorization.v1"
SCOPE_CATALOG_VERSION = "scanalyze.api.v1"
ROLE_CATALOG_VERSION = "enterprise-roles.v1"
POLICY_VERSION = "1.0.0"
POLICY_DIGEST = (
    "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
)
MEMBERSHIP_SOURCE = "pre_token_membership_v1"
TEMPORARY_GRANT_SOURCE = "authoritative_temporary_grant_store_v1"
AUTHORITATIVE_MEMBERSHIP_SOURCE = "authoritative_membership_store_v1"
AUTHORITATIVE_STATE_SCHEMA_VERSION = "authorization-authority-state.v1"
ASSURANCE_SOURCE = "authoritative_authentication_event_v1"
ASSURANCE_VERSION = "phishing-resistant-mfa.v1"
AUDIT_RECEIPT_SCHEMA_VERSION = "authorization-audit-receipt.v1"
AUDIT_REFERENCE_SCHEMA_VERSION = "authorization-audit-references.v1"
AUDIT_SINK_SOURCE = "durable_authorization_audit_sink_v1"
AUDIT_SINK_VERSION = "1.0.0"
MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS = 300
MAX_STEP_UP_AGE_SECONDS = 300
MAX_SUPPORT_GRANT_LIFETIME_SECONDS = 3600
MAX_BREAK_GLASS_GRANT_LIFETIME_SECONDS = 900
MAX_EPOCH_SECONDS = 9_999_999_999
_SUBJECT_REFERENCE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$"
)
_CUSTOMER_ID_PATTERN = re.compile(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
_DEPLOYMENT_ID_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
_VERSION_REFERENCE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)
_TEMPORARY_GRANT_ID_PATTERN = re.compile(
    r"^grant-[A-Za-z0-9][A-Za-z0-9._-]{7,127}$"
)
_OPAQUE_REFERENCE_PATTERN = re.compile(r"^ref_[0-9a-f]{24,64}$")


class Action(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class Assurance(str, Enum):
    PHISHING_RESISTANT_MFA = "phishing_resistant_mfa"


class AssuranceSource(str, Enum):
    AUTHORITATIVE_AUTHENTICATION_EVENT = ASSURANCE_SOURCE


class AssuranceVersion(str, Enum):
    PHISHING_RESISTANT_MFA_V1 = ASSURANCE_VERSION


class AuthorizationPath(str, Enum):
    MEMBERSHIP = "membership"
    TEMPORARY_GRANT = "temporary_grant"


class HumanRole(str, Enum):
    CUSTOMER_ADMIN = "customer_admin"
    DOCUMENT_OPERATOR = "document_operator"
    DOCUMENT_REVIEWER = "document_reviewer"
    AUDITOR = "auditor"


class ResourceType(str, Enum):
    DOCUMENTS = "documents"
    BATCHES = "batches"
    EMPLOYEE_PROFILES = "employee_profiles"
    RESULTS = "results"
    REVIEWS = "reviews"
    EXPORTS = "exports"
    DEPLOYMENT_CONFIGURATION = "deployment_configuration"
    METRICS = "metrics"
    AUTHORIZATION_ADMINISTRATION = "authorization_administration"
    AUDIT_LOG = "audit_log"


class DataClass(str, Enum):
    METADATA = "metadata"
    MASKED = "masked"
    CONTENT = "content"
    PII = "pii"
    AGGREGATED = "aggregated"


class OperationId(str, Enum):
    DOCUMENTS_CREATE = "documents.create"
    DOCUMENTS_SUBMIT = "documents.submit"
    DOCUMENTS_READ_METADATA = "documents.read_metadata"
    BATCHES_CREATE = "batches.create"
    BATCHES_READ_METADATA = "batches.read_metadata"
    RESULTS_READ_MASKED = "results.read_masked"
    REVIEWS_READ_METADATA = "reviews.read_metadata"
    REVIEWS_WRITE = "reviews.write"
    DEPLOYMENT_CONFIGURATION_READ = "deployment_configuration.read"
    METRICS_READ = "metrics.read"
    METRICS_READ_IDENTIFIED = "metrics.read_identified"
    AUDIT_LOG_READ = "audit_log.read"
    RESULTS_READ_FULL = "results.read_full"
    EXPORTS_EXECUTE = "exports.execute"
    ARTIFACTS_LIST_METADATA = "artifacts.list_metadata"
    ARTIFACTS_DOWNLOAD = "artifacts.download"
    EMPLOYEE_PROFILES_GENERATE = "employee_profiles.generate"
    EMPLOYEE_PROFILES_READ_JOB = "employee_profiles.read_job"
    EMPLOYEE_PROFILES_LIST_MASKED = "employee_profiles.list_masked"
    EMPLOYEE_PROFILES_READ_FULL = "employee_profiles.read_full"


@dataclass(frozen=True)
class HumanAuthorizationSnapshot:
    """Immutable, validated provider-to-PDP authorization snapshot.

    Fields are intentionally present for both paths so conflicting authority is
    detectable.  The PDP requires exactly one complete path and rejects every
    ambiguous or partially populated combination.
    """

    schema_version: str
    authorization_path: AuthorizationPath | str | None
    authorization_source: str | None
    subject: str | None
    customer_id: str | None
    deployment_id: str | None
    membership_state: str | None
    role_id: HumanRole | str | None
    membership_version: str | None
    temporary_grant_id: str | None
    temporary_grant_type: str | None
    temporary_grant_state: str | None
    temporary_grant_version: str | None
    allowed_operation_ids: FrozenSet[str]
    allowed_data_classes: FrozenSet[str]
    expires_at_epoch: int | None
    authz_schema_version: str | None
    scope_catalog_version: str | None
    role_catalog_version: str | None
    policy_version: str | None
    policy_digest: str | None
    issued_at_epoch: int | None
    assurance: Assurance | str | None
    authenticated_at_epoch: int | None
    grant_issued_at_epoch: int | None = None
    assurance_source: AssuranceSource | str | None = None
    assurance_version: AssuranceVersion | str | None = None
    authentication_event_reference: str | None = None
    case_reference: str | None = None
    incident_reference: str | None = None
    purpose_reference: str | None = None
    approval_references: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_operation_ids", frozenset(self.allowed_operation_ids))
        object.__setattr__(self, "allowed_data_classes", frozenset(self.allowed_data_classes))
        object.__setattr__(self, "approval_references", frozenset(self.approval_references))

    @property
    def issued_at(self) -> int | None:
        """Provider-adapter alias retained for a concise AuthContext API."""
        return self.issued_at_epoch

    @property
    def authenticated_at(self) -> int | None:
        """Provider-adapter alias retained for a concise AuthContext API."""
        return self.authenticated_at_epoch


@dataclass(frozen=True)
class AuthoritativeMembershipEvidence:
    """Current immutable membership state returned by a trusted resolver."""

    schema_version: str
    authorization_path: AuthorizationPath | str
    authority_source: str
    checked_at_epoch: int
    subject: str
    customer_id: str
    deployment_id: str
    membership_state: str
    role_id: HumanRole | str
    membership_version: str


@dataclass(frozen=True)
class AuthoritativeTemporaryGrantEvidence:
    """Current immutable grant state returned by a trusted resolver."""

    schema_version: str
    authorization_path: AuthorizationPath | str
    authority_source: str
    checked_at_epoch: int
    subject: str
    customer_id: str
    deployment_id: str
    temporary_grant_id: str
    temporary_grant_type: str
    temporary_grant_state: str
    temporary_grant_version: str
    grant_issued_at_epoch: int
    expires_at_epoch: int
    allowed_operation_ids: FrozenSet[str]
    allowed_data_classes: FrozenSet[str]
    case_reference: str | None = None
    incident_reference: str | None = None
    purpose_reference: str | None = None
    approval_references: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_operation_ids",
            frozenset(self.allowed_operation_ids),
        )
        object.__setattr__(
            self,
            "allowed_data_classes",
            frozenset(self.allowed_data_classes),
        )
        object.__setattr__(
            self,
            "approval_references",
            frozenset(self.approval_references),
        )


AuthoritativeStateEvidence = (
    AuthoritativeMembershipEvidence | AuthoritativeTemporaryGrantEvidence
)


@dataclass(frozen=True)
class DurableAuditReceipt:
    """Durable sink acknowledgement bound to one exact decision event."""

    schema_version: str
    sink_source: str
    sink_version: str
    decision_id: str
    receipt_reference: str
    acknowledged_at_epoch: int


@dataclass(frozen=True)
class AuthorizationAuditReferences:
    """Trusted pseudonymous bindings for one request's audit events."""

    schema_version: str
    principal_reference: str
    customer_reference: str
    deployment_reference: str
    correlation_reference: str
    grant_reference: str | None = None


@dataclass(frozen=True)
class EnterpriseAuthorizationRuntime:
    """Trusted runtime dependencies injected at the application boundary."""

    authoritative_state_resolver: Callable[
        [HumanAuthorizationSnapshot, OperationId, int],
        AuthoritativeStateEvidence,
    ]
    audit_sink: Callable[[Mapping[str, Any]], DurableAuditReceipt]
    audit_reference_resolver: Callable[
        ["AuthContext", OperationId, str],
        AuthorizationAuditReferences,
    ] | None = None


@dataclass(frozen=True)
class PermissionRequirement:
    resource: ResourceType
    actions: FrozenSet[Action]
    data_classes: FrozenSet[DataClass]


@dataclass(frozen=True)
class OperationPolicy:
    operation_id: OperationId
    requirements: tuple[PermissionRequirement, ...]
    m2m_required_actions: FrozenSet[str]
    step_up_required: bool = False
    temporary_grant_allowed: bool = False


def _permission(
    resource: ResourceType,
    actions: tuple[Action, ...],
    data_classes: tuple[DataClass, ...],
) -> PermissionRequirement:
    return PermissionRequirement(resource, frozenset(actions), frozenset(data_classes))


_READ = frozenset({Action.READ.value})
_WRITE = frozenset({Action.WRITE.value})
_READ_ADMIN = frozenset({Action.READ.value, Action.ADMIN.value})


OPERATION_POLICIES: Mapping[OperationId, OperationPolicy] = {
    OperationId.DOCUMENTS_CREATE: OperationPolicy(
        OperationId.DOCUMENTS_CREATE,
        (_permission(ResourceType.DOCUMENTS, (Action.WRITE,), (DataClass.CONTENT,)),),
        _WRITE,
    ),
    OperationId.DOCUMENTS_SUBMIT: OperationPolicy(
        OperationId.DOCUMENTS_SUBMIT,
        (_permission(ResourceType.DOCUMENTS, (Action.WRITE,), (DataClass.CONTENT,)),),
        _WRITE,
    ),
    OperationId.DOCUMENTS_READ_METADATA: OperationPolicy(
        OperationId.DOCUMENTS_READ_METADATA,
        (_permission(ResourceType.DOCUMENTS, (Action.READ,), (DataClass.METADATA,)),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.BATCHES_CREATE: OperationPolicy(
        OperationId.BATCHES_CREATE,
        (_permission(ResourceType.BATCHES, (Action.WRITE,), (DataClass.METADATA,)),),
        _WRITE,
    ),
    OperationId.BATCHES_READ_METADATA: OperationPolicy(
        OperationId.BATCHES_READ_METADATA,
        (_permission(ResourceType.BATCHES, (Action.READ,), (DataClass.METADATA,)),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.RESULTS_READ_MASKED: OperationPolicy(
        OperationId.RESULTS_READ_MASKED,
        (_permission(
            ResourceType.RESULTS,
            (Action.READ,),
            (DataClass.METADATA, DataClass.MASKED),
        ),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.REVIEWS_READ_METADATA: OperationPolicy(
        OperationId.REVIEWS_READ_METADATA,
        (_permission(ResourceType.REVIEWS, (Action.READ,), (DataClass.METADATA,)),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.REVIEWS_WRITE: OperationPolicy(
        OperationId.REVIEWS_WRITE,
        (_permission(ResourceType.REVIEWS, (Action.WRITE,), (DataClass.MASKED,)),),
        _WRITE,
    ),
    OperationId.DEPLOYMENT_CONFIGURATION_READ: OperationPolicy(
        OperationId.DEPLOYMENT_CONFIGURATION_READ,
        (_permission(
            ResourceType.DEPLOYMENT_CONFIGURATION,
            (Action.READ,),
            (DataClass.METADATA,),
        ),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.METRICS_READ: OperationPolicy(
        OperationId.METRICS_READ,
        (_permission(
            ResourceType.METRICS,
            (Action.READ,),
            (DataClass.METADATA, DataClass.AGGREGATED),
        ),),
        _READ,
        temporary_grant_allowed=True,
    ),
    # Existing output includes user identifiers/display values, so no v1 human
    # role possesses the required PII data class.  M2M keeps its GUG-102 action.
    OperationId.METRICS_READ_IDENTIFIED: OperationPolicy(
        OperationId.METRICS_READ_IDENTIFIED,
        (_permission(
            ResourceType.METRICS,
            (Action.READ,),
            (DataClass.METADATA, DataClass.AGGREGATED, DataClass.PII),
        ),),
        _READ,
    ),
    OperationId.AUDIT_LOG_READ: OperationPolicy(
        OperationId.AUDIT_LOG_READ,
        (_permission(ResourceType.AUDIT_LOG, (Action.READ,), (DataClass.METADATA,)),),
        _READ,
        temporary_grant_allowed=True,
    ),
    OperationId.RESULTS_READ_FULL: OperationPolicy(
        OperationId.RESULTS_READ_FULL,
        (_permission(
            ResourceType.RESULTS,
            (Action.READ, Action.ADMIN),
            (DataClass.CONTENT, DataClass.PII),
        ),),
        _READ_ADMIN,
        step_up_required=True,
    ),
    OperationId.EXPORTS_EXECUTE: OperationPolicy(
        OperationId.EXPORTS_EXECUTE,
        (_permission(
            ResourceType.EXPORTS,
            (Action.READ, Action.ADMIN),
            (DataClass.CONTENT, DataClass.PII),
        ),),
        _READ_ADMIN,
        step_up_required=True,
    ),
    # Artifact metadata currently carries internal locators.  Human access is
    # conservatively privileged until a versioned locator-free API exists.
    OperationId.ARTIFACTS_LIST_METADATA: OperationPolicy(
        OperationId.ARTIFACTS_LIST_METADATA,
        (_permission(
            ResourceType.DOCUMENTS,
            (Action.READ, Action.ADMIN),
            (DataClass.CONTENT,),
        ),),
        _READ,
        step_up_required=True,
    ),
    OperationId.ARTIFACTS_DOWNLOAD: OperationPolicy(
        OperationId.ARTIFACTS_DOWNLOAD,
        (_permission(
            ResourceType.DOCUMENTS,
            (Action.READ, Action.ADMIN),
            (DataClass.CONTENT,),
        ),),
        _READ_ADMIN,
        step_up_required=True,
    ),
    # Generation creates a full-PII profile.  The v1 operator role only has
    # metadata/masked profile data classes, so this remains admin-only.
    OperationId.EMPLOYEE_PROFILES_GENERATE: OperationPolicy(
        OperationId.EMPLOYEE_PROFILES_GENERATE,
        (_permission(
            ResourceType.EMPLOYEE_PROFILES,
            (Action.WRITE,),
            (DataClass.PII,),
        ),),
        _WRITE,
    ),
    OperationId.EMPLOYEE_PROFILES_READ_JOB: OperationPolicy(
        OperationId.EMPLOYEE_PROFILES_READ_JOB,
        (_permission(
            ResourceType.EMPLOYEE_PROFILES,
            (Action.READ,),
            (DataClass.METADATA,),
        ),),
        _READ,
    ),
    OperationId.EMPLOYEE_PROFILES_LIST_MASKED: OperationPolicy(
        OperationId.EMPLOYEE_PROFILES_LIST_MASKED,
        (_permission(
            ResourceType.EMPLOYEE_PROFILES,
            (Action.READ,),
            (DataClass.METADATA, DataClass.MASKED),
        ),),
        _READ_ADMIN,
    ),
    OperationId.EMPLOYEE_PROFILES_READ_FULL: OperationPolicy(
        OperationId.EMPLOYEE_PROFILES_READ_FULL,
        (_permission(
            ResourceType.EMPLOYEE_PROFILES,
            (Action.READ, Action.ADMIN),
            (DataClass.PII,),
        ),),
        _READ_ADMIN,
        step_up_required=True,
    ),
}


_ROLE_PERMISSIONS: Mapping[
    HumanRole,
    Mapping[ResourceType, tuple[FrozenSet[Action], FrozenSet[DataClass]]],
] = {
    HumanRole.CUSTOMER_ADMIN: {
        ResourceType.DOCUMENTS: (
            frozenset({Action.READ, Action.WRITE, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT, DataClass.PII}),
        ),
        ResourceType.BATCHES: (
            frozenset({Action.READ, Action.WRITE, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT, DataClass.PII}),
        ),
        ResourceType.EMPLOYEE_PROFILES: (
            frozenset({Action.READ, Action.WRITE, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT, DataClass.PII}),
        ),
        ResourceType.RESULTS: (
            frozenset({Action.READ, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT, DataClass.PII}),
        ),
        ResourceType.REVIEWS: (
            frozenset({Action.READ, Action.WRITE, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT}),
        ),
        ResourceType.EXPORTS: (
            frozenset({Action.READ, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.CONTENT, DataClass.PII}),
        ),
        ResourceType.DEPLOYMENT_CONFIGURATION: (
            frozenset({Action.READ, Action.ADMIN}),
            frozenset({DataClass.METADATA}),
        ),
        ResourceType.METRICS: (
            frozenset({Action.READ, Action.ADMIN}),
            frozenset({DataClass.METADATA, DataClass.AGGREGATED}),
        ),
        ResourceType.AUTHORIZATION_ADMINISTRATION: (
            frozenset({Action.READ, Action.ADMIN}),
            frozenset({DataClass.METADATA}),
        ),
        ResourceType.AUDIT_LOG: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA}),
        ),
    },
    HumanRole.DOCUMENT_OPERATOR: {
        ResourceType.DOCUMENTS: (
            frozenset({Action.READ, Action.WRITE}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT}),
        ),
        ResourceType.BATCHES: (
            frozenset({Action.READ, Action.WRITE}),
            frozenset({DataClass.METADATA, DataClass.MASKED, DataClass.CONTENT}),
        ),
        ResourceType.EMPLOYEE_PROFILES: (
            frozenset({Action.READ, Action.WRITE}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.RESULTS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.REVIEWS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.METRICS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.AGGREGATED}),
        ),
    },
    HumanRole.DOCUMENT_REVIEWER: {
        ResourceType.DOCUMENTS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.BATCHES: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.EMPLOYEE_PROFILES: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.RESULTS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
        ResourceType.REVIEWS: (
            frozenset({Action.READ, Action.WRITE}),
            frozenset({DataClass.METADATA, DataClass.MASKED}),
        ),
    },
    HumanRole.AUDITOR: {
        ResourceType.AUDIT_LOG: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA}),
        ),
        ResourceType.METRICS: (
            frozenset({Action.READ}),
            frozenset({DataClass.METADATA, DataClass.AGGREGATED}),
        ),
    },
}


_TEMPORARY_GRANT_OPERATIONS = frozenset(
    {
        OperationId.DOCUMENTS_READ_METADATA.value,
        OperationId.BATCHES_READ_METADATA.value,
        OperationId.RESULTS_READ_MASKED.value,
        OperationId.REVIEWS_READ_METADATA.value,
        OperationId.DEPLOYMENT_CONFIGURATION_READ.value,
        OperationId.METRICS_READ.value,
        OperationId.AUDIT_LOG_READ.value,
    }
)

_ACTION_SCOPES = {
    Action.READ: "scanalyze.api.v1/read",
    Action.WRITE: "scanalyze.api.v1/write",
    Action.ADMIN: "scanalyze.api.v1/admin",
}

_DATA_CLASS_VALUES = frozenset(item.value for item in DataClass)


def is_valid_subject_reference(value: Any) -> bool:
    """Return whether a subject matches the canonical portable schema."""
    return isinstance(value, str) and bool(_SUBJECT_REFERENCE_PATTERN.fullmatch(value))


def is_valid_version_reference(value: Any) -> bool:
    """Return whether a version matches every runtime and schema boundary."""
    return isinstance(value, str) and bool(_VERSION_REFERENCE_PATTERN.fullmatch(value))


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_epoch(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= MAX_EPOCH_SECONDS
    )


def _constant_time_equal(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and hmac.compare_digest(
        actual.encode("utf-8"), expected.encode("utf-8")
    )


def _deny(reason: str) -> None:
    logger.warning("enterprise_authorization_denied", reason=reason)
    error = AppError(
        code="FORBIDDEN",
        message="Principal is not authorized for this operation",
        status_code=403,
        details={},
    )
    setattr(error, "authorization_reason", reason)
    raise error


def _coerce_operation(operation_id: OperationId | str) -> OperationId:
    try:
        return operation_id if isinstance(operation_id, OperationId) else OperationId(operation_id)
    except (TypeError, ValueError):
        _deny("unknown_operation")


def _validate_common_snapshot(
    auth: "AuthContext",
    snapshot: HumanAuthorizationSnapshot,
    *,
    now_epoch: int,
) -> None:
    if not is_valid_subject_reference(auth.subject):
        _deny("malformed_subject")
    if not is_valid_subject_reference(snapshot.subject):
        _deny("malformed_subject")
    if snapshot.subject != auth.subject:
        _deny("conflicting_subject")
    if not (
        isinstance(auth.customer_id, str)
        and _CUSTOMER_ID_PATTERN.fullmatch(auth.customer_id)
        and isinstance(snapshot.customer_id, str)
        and _CUSTOMER_ID_PATTERN.fullmatch(snapshot.customer_id)
    ):
        _deny("malformed_customer_binding")
    if snapshot.customer_id != auth.customer_id:
        _deny("foreign_customer")
    if not (
        isinstance(auth.deployment_id, str)
        and _DEPLOYMENT_ID_PATTERN.fullmatch(auth.deployment_id)
        and isinstance(snapshot.deployment_id, str)
        and _DEPLOYMENT_ID_PATTERN.fullmatch(snapshot.deployment_id)
    ):
        _deny("malformed_deployment_binding")
    if snapshot.deployment_id != auth.deployment_id:
        _deny("foreign_deployment")
    if snapshot.schema_version != AUTHORIZATION_CONTEXT_SCHEMA_VERSION:
        _deny("unsupported_authorization_context_schema")
    if snapshot.authz_schema_version != AUTHZ_SCHEMA_VERSION:
        _deny("unsupported_authz_schema")
    if snapshot.scope_catalog_version != SCOPE_CATALOG_VERSION:
        _deny("unsupported_scope_catalog")
    if snapshot.role_catalog_version != ROLE_CATALOG_VERSION:
        _deny("unsupported_role_catalog")
    if snapshot.policy_version != POLICY_VERSION:
        _deny("unsupported_policy_version")
    if not _constant_time_equal(snapshot.policy_digest, POLICY_DIGEST):
        _deny("policy_digest_mismatch")
    if not _valid_epoch(now_epoch):
        _deny("invalid_decision_time")
    if not _valid_epoch(snapshot.issued_at_epoch):
        _deny("missing_membership_snapshot_time")
    assert snapshot.issued_at_epoch is not None
    snapshot_age = now_epoch - snapshot.issued_at_epoch
    if snapshot_age < 0 or snapshot_age > MAX_MEMBERSHIP_SNAPSHOT_AGE_SECONDS:
        _deny("stale_membership_snapshot")
    if not _valid_epoch(snapshot.authenticated_at_epoch):
        _deny("missing_authentication_time")
    assert snapshot.authenticated_at_epoch is not None
    if snapshot.authenticated_at_epoch > snapshot.issued_at_epoch:
        _deny("conflicting_authentication_time")
    assurance = (
        snapshot.assurance.value
        if isinstance(snapshot.assurance, Assurance)
        else snapshot.assurance
    )
    provenance = (
        snapshot.assurance_source,
        snapshot.assurance_version,
        snapshot.authentication_event_reference,
    )
    if assurance is None and all(value is None for value in provenance):
        return
    if (
        assurance != Assurance.PHISHING_RESISTANT_MFA.value
        or snapshot.assurance_source != ASSURANCE_SOURCE
        or snapshot.assurance_version != ASSURANCE_VERSION
        or not isinstance(snapshot.authentication_event_reference, str)
        or not _OPAQUE_REFERENCE_PATTERN.fullmatch(
            snapshot.authentication_event_reference
        )
    ):
        _deny("malformed_assurance_evidence")


def _validate_membership_snapshot(snapshot: HumanAuthorizationSnapshot) -> HumanRole:
    if snapshot.authorization_source != MEMBERSHIP_SOURCE:
        _deny("untrusted_membership_source")
    if snapshot.membership_state != "active":
        _deny("inactive_membership")
    if not is_valid_version_reference(snapshot.membership_version):
        _deny("malformed_membership_version")
    try:
        role = snapshot.role_id if isinstance(snapshot.role_id, HumanRole) else HumanRole(snapshot.role_id)
    except (TypeError, ValueError):
        _deny("unknown_role")
    if any(
        value is not None
        for value in (
            snapshot.temporary_grant_id,
            snapshot.temporary_grant_type,
            snapshot.temporary_grant_state,
            snapshot.temporary_grant_version,
            snapshot.grant_issued_at_epoch,
            snapshot.expires_at_epoch,
            snapshot.case_reference,
            snapshot.incident_reference,
            snapshot.purpose_reference,
        )
    ) or (
        snapshot.allowed_operation_ids
        or snapshot.allowed_data_classes
        or snapshot.approval_references
    ):
        _deny("conflicting_authorization_paths")
    return role


def _role_allows(role: HumanRole, policy: OperationPolicy) -> bool:
    permissions = _ROLE_PERMISSIONS.get(role, {})
    for requirement in policy.requirements:
        granted = permissions.get(requirement.resource)
        if granted is None:
            return False
        granted_actions, granted_data_classes = granted
        if not requirement.actions.issubset(granted_actions):
            return False
        if not requirement.data_classes.issubset(granted_data_classes):
            return False
    return True


def _validate_temporary_grant(
    snapshot: HumanAuthorizationSnapshot,
    policy: OperationPolicy,
    *,
    now_epoch: int,
) -> None:
    if snapshot.authorization_source != TEMPORARY_GRANT_SOURCE:
        _deny("untrusted_temporary_grant_source")
    if any(
        value is not None
        for value in (
            snapshot.membership_state,
            snapshot.role_id,
            snapshot.membership_version,
        )
    ):
        _deny("conflicting_authorization_paths")
    if snapshot.temporary_grant_type not in {"support", "break_glass"}:
        _deny("unknown_temporary_grant_type")
    if snapshot.temporary_grant_state != "active":
        _deny("inactive_temporary_grant")
    if not (
        isinstance(snapshot.temporary_grant_id, str)
        and _TEMPORARY_GRANT_ID_PATTERN.fullmatch(snapshot.temporary_grant_id)
    ):
        _deny("malformed_temporary_grant")
    if not is_valid_version_reference(snapshot.temporary_grant_version):
        _deny("malformed_temporary_grant_version")
    if not (
        isinstance(snapshot.purpose_reference, str)
        and _OPAQUE_REFERENCE_PATTERN.fullmatch(snapshot.purpose_reference)
    ):
        _deny("missing_temporary_grant_purpose")
    if (
        not snapshot.approval_references
        or len(snapshot.approval_references) > 4
        or any(
            not isinstance(reference, str)
            or not _OPAQUE_REFERENCE_PATTERN.fullmatch(reference)
            for reference in snapshot.approval_references
        )
    ):
        _deny("invalid_temporary_grant_approvals")
    if opaque_log_reference(snapshot.subject) in snapshot.approval_references:
        _deny("self_approved_temporary_grant")
    if snapshot.temporary_grant_type == "support":
        if not (
            isinstance(snapshot.case_reference, str)
            and _OPAQUE_REFERENCE_PATTERN.fullmatch(snapshot.case_reference)
        ) or snapshot.incident_reference is not None:
            _deny("invalid_support_case_binding")
    elif (
        not isinstance(snapshot.incident_reference, str)
        or not _OPAQUE_REFERENCE_PATTERN.fullmatch(snapshot.incident_reference)
        or snapshot.case_reference is not None
        or len(snapshot.approval_references) != 2
    ):
        _deny("invalid_break_glass_approval_binding")
    if not _valid_epoch(snapshot.grant_issued_at_epoch):
        _deny("missing_temporary_grant_issued_at")
    if not _valid_epoch(snapshot.expires_at_epoch) or snapshot.expires_at_epoch <= now_epoch:
        _deny("expired_temporary_grant")
    assert snapshot.grant_issued_at_epoch is not None
    assert snapshot.expires_at_epoch is not None
    if snapshot.grant_issued_at_epoch > now_epoch:
        _deny("future_temporary_grant")
    max_lifetime = (
        MAX_SUPPORT_GRANT_LIFETIME_SECONDS
        if snapshot.temporary_grant_type == "support"
        else MAX_BREAK_GLASS_GRANT_LIFETIME_SECONDS
    )
    lifetime = snapshot.expires_at_epoch - snapshot.grant_issued_at_epoch
    if lifetime <= 0 or lifetime > max_lifetime:
        _deny("temporary_grant_lifetime_exceeded")
    if not policy.temporary_grant_allowed:
        _deny("temporary_grant_sensitive_or_unmapped")
    if not snapshot.allowed_operation_ids or not snapshot.allowed_data_classes:
        _deny("incomplete_temporary_grant")
    if not snapshot.allowed_operation_ids.issubset(_TEMPORARY_GRANT_OPERATIONS):
        _deny("unknown_temporary_grant_operation")
    if (
        len(snapshot.allowed_data_classes) > len(_DATA_CLASS_VALUES)
        or not snapshot.allowed_data_classes.issubset(_DATA_CLASS_VALUES)
    ):
        _deny("unknown_temporary_grant_data_class")
    if policy.operation_id.value not in snapshot.allowed_operation_ids:
        _deny("operation_not_in_temporary_grant")
    required_data_classes = frozenset(
        item.value
        for requirement in policy.requirements
        for item in requirement.data_classes
    )
    if not required_data_classes.issubset(snapshot.allowed_data_classes):
        _deny("data_class_not_in_temporary_grant")
    _require_step_up(snapshot, now_epoch=now_epoch)


def _validate_authoritative_evidence_common(
    evidence: AuthoritativeStateEvidence,
    *,
    now_epoch: int,
) -> None:
    if evidence.schema_version != AUTHORITATIVE_STATE_SCHEMA_VERSION:
        _deny("unsupported_authoritative_state_schema")
    if not _valid_epoch(evidence.checked_at_epoch):
        _deny("missing_authoritative_state_time")
    if evidence.checked_at_epoch != now_epoch:
        _deny("stale_authoritative_state")


def _validate_authoritative_membership(
    snapshot: HumanAuthorizationSnapshot,
    evidence: AuthoritativeMembershipEvidence,
    *,
    now_epoch: int,
) -> None:
    _validate_authoritative_evidence_common(evidence, now_epoch=now_epoch)
    path = (
        evidence.authorization_path.value
        if isinstance(evidence.authorization_path, AuthorizationPath)
        else evidence.authorization_path
    )
    if path != AuthorizationPath.MEMBERSHIP.value:
        _deny("conflicting_authoritative_membership_path")
    if evidence.authority_source != AUTHORITATIVE_MEMBERSHIP_SOURCE:
        _deny("untrusted_authoritative_membership_source")
    expected = (
        snapshot.subject,
        snapshot.customer_id,
        snapshot.deployment_id,
        snapshot.membership_state,
        snapshot.membership_version,
    )
    actual = (
        evidence.subject,
        evidence.customer_id,
        evidence.deployment_id,
        evidence.membership_state,
        evidence.membership_version,
    )
    if actual != expected:
        _deny("authoritative_membership_mismatch")
    expected_role = (
        snapshot.role_id.value
        if isinstance(snapshot.role_id, HumanRole)
        else snapshot.role_id
    )
    actual_role = (
        evidence.role_id.value
        if isinstance(evidence.role_id, HumanRole)
        else evidence.role_id
    )
    if actual_role != expected_role:
        _deny("authoritative_membership_role_mismatch")


def _validate_authoritative_temporary_grant(
    snapshot: HumanAuthorizationSnapshot,
    evidence: AuthoritativeTemporaryGrantEvidence,
    *,
    now_epoch: int,
) -> None:
    _validate_authoritative_evidence_common(evidence, now_epoch=now_epoch)
    path = (
        evidence.authorization_path.value
        if isinstance(evidence.authorization_path, AuthorizationPath)
        else evidence.authorization_path
    )
    if path != AuthorizationPath.TEMPORARY_GRANT.value:
        _deny("conflicting_authoritative_temporary_grant_path")
    if evidence.authority_source != TEMPORARY_GRANT_SOURCE:
        _deny("untrusted_authoritative_temporary_grant_source")
    expected = (
        snapshot.subject,
        snapshot.customer_id,
        snapshot.deployment_id,
        snapshot.temporary_grant_id,
        snapshot.temporary_grant_type,
        snapshot.temporary_grant_state,
        snapshot.temporary_grant_version,
        snapshot.grant_issued_at_epoch,
        snapshot.expires_at_epoch,
        snapshot.allowed_operation_ids,
        snapshot.allowed_data_classes,
        snapshot.case_reference,
        snapshot.incident_reference,
        snapshot.purpose_reference,
        snapshot.approval_references,
    )
    actual = (
        evidence.subject,
        evidence.customer_id,
        evidence.deployment_id,
        evidence.temporary_grant_id,
        evidence.temporary_grant_type,
        evidence.temporary_grant_state,
        evidence.temporary_grant_version,
        evidence.grant_issued_at_epoch,
        evidence.expires_at_epoch,
        evidence.allowed_operation_ids,
        evidence.allowed_data_classes,
        evidence.case_reference,
        evidence.incident_reference,
        evidence.purpose_reference,
        evidence.approval_references,
    )
    if actual != expected:
        _deny("authoritative_temporary_grant_mismatch")


def _require_authoritative_state(
    runtime: EnterpriseAuthorizationRuntime | None,
    snapshot: HumanAuthorizationSnapshot,
    operation: OperationId,
    path: AuthorizationPath,
    *,
    now_epoch: int,
) -> None:
    if not isinstance(runtime, EnterpriseAuthorizationRuntime) or not callable(
        runtime.authoritative_state_resolver
    ):
        _deny("authoritative_state_runtime_unavailable")
    try:
        evidence = runtime.authoritative_state_resolver(
            snapshot,
            operation,
            now_epoch,
        )
    except Exception:
        _deny("authoritative_state_unavailable")
    if path is AuthorizationPath.MEMBERSHIP:
        if not isinstance(evidence, AuthoritativeMembershipEvidence):
            _deny("invalid_authoritative_membership_evidence")
        _validate_authoritative_membership(snapshot, evidence, now_epoch=now_epoch)
        return
    if path is AuthorizationPath.TEMPORARY_GRANT:
        if not isinstance(evidence, AuthoritativeTemporaryGrantEvidence):
            _deny("invalid_authoritative_temporary_grant_evidence")
        _validate_authoritative_temporary_grant(snapshot, evidence, now_epoch=now_epoch)
        return
    _deny("unknown_authorization_path")


def _require_step_up(
    snapshot: HumanAuthorizationSnapshot,
    *,
    now_epoch: int,
) -> None:
    assurance = (
        snapshot.assurance.value
        if isinstance(snapshot.assurance, Assurance)
        else snapshot.assurance
    )
    if assurance != Assurance.PHISHING_RESISTANT_MFA.value:
        _deny("insufficient_assurance")
    if snapshot.assurance_source != ASSURANCE_SOURCE:
        _deny("untrusted_assurance_source")
    if snapshot.assurance_version != ASSURANCE_VERSION:
        _deny("unsupported_assurance_version")
    if not (
        isinstance(snapshot.authentication_event_reference, str)
        and _OPAQUE_REFERENCE_PATTERN.fullmatch(snapshot.authentication_event_reference)
    ):
        _deny("invalid_assurance_event_reference")
    if not _valid_epoch(snapshot.authenticated_at_epoch):
        _deny("missing_authentication_time")
    assert snapshot.authenticated_at_epoch is not None
    age = now_epoch - snapshot.authenticated_at_epoch
    if age < 0 or age > MAX_STEP_UP_AGE_SECONDS:
        _deny("stale_step_up")


def _required_human_scopes(policy: OperationPolicy) -> FrozenSet[str]:
    return frozenset(
        _ACTION_SCOPES[action]
        for requirement in policy.requirements
        for action in requirement.actions
    )


def _resolve_audit_references(
    runtime: EnterpriseAuthorizationRuntime,
    auth: "AuthContext",
    operation: OperationId,
) -> AuthorizationAuditReferences:
    resolver = runtime.audit_reference_resolver
    if not callable(resolver):
        _deny("audit_reference_resolver_unavailable")
    correlation_reference = current_log_reference(
        "correlationId",
        f"{getattr(auth, 'subject', 'unknown')}:{operation.value}",
    )
    try:
        references = resolver(auth, operation, correlation_reference)
    except Exception:
        _deny("audit_reference_resolution_failed")
    if not isinstance(references, AuthorizationAuditReferences):
        _deny("invalid_audit_references")
    if references.schema_version != AUDIT_REFERENCE_SCHEMA_VERSION:
        _deny("unsupported_audit_reference_schema")
    required_references = (
        references.principal_reference,
        references.customer_reference,
        references.deployment_reference,
        references.correlation_reference,
    )
    if any(
        not isinstance(reference, str)
        or not _OPAQUE_REFERENCE_PATTERN.fullmatch(reference)
        for reference in required_references
    ):
        _deny("invalid_audit_references")
    if references.correlation_reference != correlation_reference:
        _deny("audit_correlation_mismatch")
    snapshot = getattr(auth, "human_authorization", None)
    path = getattr(snapshot, "authorization_path", None)
    if isinstance(path, AuthorizationPath):
        path = path.value
    if path == AuthorizationPath.TEMPORARY_GRANT.value:
        if not (
            isinstance(references.grant_reference, str)
            and _OPAQUE_REFERENCE_PATTERN.fullmatch(references.grant_reference)
        ):
            _deny("invalid_audit_grant_reference")
    elif references.grant_reference is not None:
        _deny("conflicting_audit_grant_reference")
    return references


def _decision_event(
    *,
    auth: "AuthContext",
    policy: OperationPolicy,
    decision: str,
    reason: str,
    now_epoch: int,
    audit_references: AuthorizationAuditReferences | None = None,
) -> dict[str, Any]:
    snapshot = getattr(auth, "human_authorization", None)
    assurance = getattr(snapshot, "assurance", None)
    if isinstance(assurance, Assurance):
        assurance = assurance.value
    required_actions = {
        action for requirement in policy.requirements for action in requirement.actions
    }
    actions = [
        action.value
        for action in (Action.READ, Action.WRITE, Action.ADMIN)
        if action in required_actions
    ]
    principal_type = str(getattr(auth, "principal_type", "unknown"))
    if principal_type == "m2m":
        assurance = "validated_client_credentials_binding"
    elif assurance is None:
        assurance = "none"

    decision_id = f"decision-{uuid.uuid4().hex}"
    principal_identity = (
        getattr(auth, "subject", None)
        or getattr(auth, "client_id", None)
        or "unknown-principal"
    )
    if audit_references is None:
        principal_reference = opaque_log_reference(principal_identity)
        customer_reference = opaque_log_reference(
            getattr(auth, "customer_id", "unknown-customer")
        )
        deployment_reference = opaque_log_reference(
            getattr(auth, "deployment_id", "unknown-deployment")
        )
        correlation_reference = current_log_reference("correlationId", decision_id)
    else:
        principal_reference = audit_references.principal_reference
        customer_reference = audit_references.customer_reference
        deployment_reference = audit_references.deployment_reference
        correlation_reference = audit_references.correlation_reference

    event: dict[str, Any] = {
        "event_schema_version": "authorization-decision.v1",
        "timestamp": datetime.fromtimestamp(now_epoch, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "decision_id": decision_id,
        "principal_type": principal_type,
        "principal_reference": principal_reference,
        "customer_reference": customer_reference,
        "deployment_reference": deployment_reference,
        "correlation_reference": correlation_reference,
        "action": "+".join(actions) if actions else "none",
        "operation": policy.operation_id.value,
        "resource_type": policy.requirements[0].resource.value,
        "decision": decision,
        "reason_code": reason,
        "policy_version": POLICY_VERSION,
        "policy_digest": POLICY_DIGEST,
        "assurance": str(assurance),
    }

    if principal_type == "m2m":
        event["authorization_path"] = "m2m_binding"
        event["authorization_source"] = "m2m_identity_binding_v1"
        event["grant_version"] = "m2m_identity_binding_v1"
        return event

    path = getattr(snapshot, "authorization_path", None)
    if isinstance(path, AuthorizationPath):
        path = path.value
    source = getattr(snapshot, "authorization_source", None)
    if path in {item.value for item in AuthorizationPath}:
        event["authorization_path"] = str(path)
    if source in {MEMBERSHIP_SOURCE, TEMPORARY_GRANT_SOURCE}:
        event["authorization_source"] = str(source)
    if path == AuthorizationPath.MEMBERSHIP.value:
        membership_version = getattr(snapshot, "membership_version", None)
        if is_valid_version_reference(membership_version):
            event["membership_version"] = str(membership_version)
            event["role_catalog_version"] = ROLE_CATALOG_VERSION
    elif path == AuthorizationPath.TEMPORARY_GRANT.value:
        temporary_grant_version = getattr(snapshot, "temporary_grant_version", None)
        temporary_grant_type = getattr(snapshot, "temporary_grant_type", None)
        temporary_grant_state = getattr(snapshot, "temporary_grant_state", None)
        temporary_grant_id = getattr(snapshot, "temporary_grant_id", None)
        if is_valid_version_reference(temporary_grant_version):
            event["temporary_grant_version"] = str(temporary_grant_version)
        if audit_references is not None and audit_references.grant_reference is not None:
            event["grant_reference"] = audit_references.grant_reference
        elif isinstance(temporary_grant_id, str):
            event["grant_reference"] = opaque_log_reference(temporary_grant_id)
        if temporary_grant_type in {"support", "break_glass"}:
            event["temporary_grant_type"] = str(temporary_grant_type)
        if temporary_grant_state == "active":
            event["temporary_grant_state"] = "active"
        for field in ("case_reference", "incident_reference", "purpose_reference"):
            value = getattr(snapshot, field, None)
            if isinstance(value, str) and _OPAQUE_REFERENCE_PATTERN.fullmatch(value):
                event[field] = value
        approval_references = getattr(snapshot, "approval_references", frozenset())
        if approval_references and all(
            isinstance(reference, str)
            and _OPAQUE_REFERENCE_PATTERN.fullmatch(reference)
            for reference in approval_references
        ):
            event["approval_references"] = sorted(approval_references)
    return event


def _default_audit_sink(event: Mapping[str, Any]) -> None:
    logger.info("authorization_decision", **dict(event))


def _validate_durable_audit_receipt(
    event: Mapping[str, Any],
    receipt: Any,
    *,
    now_epoch: int,
) -> None:
    if not isinstance(receipt, DurableAuditReceipt):
        _deny("missing_durable_audit_receipt")
    if receipt.schema_version != AUDIT_RECEIPT_SCHEMA_VERSION:
        _deny("unsupported_audit_receipt_schema")
    if receipt.sink_source != AUDIT_SINK_SOURCE:
        _deny("untrusted_audit_sink_source")
    if receipt.sink_version != AUDIT_SINK_VERSION:
        _deny("unsupported_audit_sink_version")
    if receipt.decision_id != event.get("decision_id"):
        _deny("audit_receipt_decision_mismatch")
    if not (
        isinstance(receipt.receipt_reference, str)
        and _OPAQUE_REFERENCE_PATTERN.fullmatch(receipt.receipt_reference)
    ):
        _deny("invalid_audit_receipt_reference")
    if (
        not _valid_epoch(receipt.acknowledged_at_epoch)
        or receipt.acknowledged_at_epoch < now_epoch
        or receipt.acknowledged_at_epoch > now_epoch + 30
    ):
        _deny("invalid_audit_receipt_time")


def _emit_allow(
    auth: "AuthContext",
    policy: OperationPolicy,
    *,
    now_epoch: int,
    audit_sink: Callable[[Mapping[str, Any]], Any] | None,
    durable_receipt_required: bool,
    audit_references: AuthorizationAuditReferences | None = None,
) -> None:
    event = _decision_event(
        auth=auth,
        policy=policy,
        decision="allow",
        reason="explicit_allow",
        now_epoch=now_epoch,
        audit_references=audit_references,
    )
    try:
        receipt = (audit_sink or _default_audit_sink)(event)
    except Exception:
        _deny("audit_unavailable")
    if durable_receipt_required:
        _validate_durable_audit_receipt(event, receipt, now_epoch=now_epoch)


def _emit_deny(
    auth: "AuthContext",
    policy: OperationPolicy,
    *,
    reason: str,
    now_epoch: int,
    audit_sink: Callable[[Mapping[str, Any]], Any] | None,
) -> None:
    """Best-effort denial evidence; an unavailable sink never changes denial."""
    principal_type = getattr(auth, "principal_type", None)
    if principal_type not in {"user", "m2m"}:
        return
    event = _decision_event(
        auth=auth,
        policy=policy,
        decision="deny",
        reason=reason,
        now_epoch=now_epoch,
    )
    try:
        (audit_sink or _default_audit_sink)(event)
    except Exception:
        logger.warning("authorization_denial_audit_unavailable")


def authorize_operation(
    auth: "AuthContext",
    operation_id: OperationId | str,
    *,
    now_epoch: int | None = None,
    runtime: EnterpriseAuthorizationRuntime | None = None,
    audit_sink: Callable[[Mapping[str, Any]], Any] | None = None,
) -> "AuthContext":
    """Authorize one closed operation before any protected handler effect."""

    operation = _coerce_operation(operation_id)
    policy = OPERATION_POLICIES.get(operation)
    if policy is None:  # defensive against an incomplete future enum addition
        _deny("unmapped_operation")
    decision_time = int(time.time()) if now_epoch is None else now_epoch
    if not _valid_epoch(decision_time):
        _deny("invalid_decision_time")
    if auth is None:
        _deny("missing_auth_context")

    resolved_audit_references: AuthorizationAuditReferences | None = None
    try:
        principal_type = getattr(auth, "principal_type", None)
        if principal_type == "m2m":
            if getattr(auth, "human_authorization", None) is not None:
                _deny("conflicting_principal_context")
            if getattr(auth, "auth_source", None) != "m2m_identity_binding_v1":
                _deny("untrusted_m2m_source")
            if not policy.m2m_required_actions.issubset(
                getattr(auth, "granted_actions", frozenset())
            ):
                _deny("missing_m2m_action")
        elif principal_type == "user":
            snapshot = getattr(auth, "human_authorization", None)
            if not isinstance(snapshot, HumanAuthorizationSnapshot):
                _deny("missing_human_authorization")
            _validate_common_snapshot(auth, snapshot, now_epoch=decision_time)
            if not _required_human_scopes(policy).issubset(
                getattr(auth, "scopes", frozenset())
            ):
                _deny("missing_required_scope")

            try:
                path = (
                    snapshot.authorization_path
                    if isinstance(snapshot.authorization_path, AuthorizationPath)
                    else AuthorizationPath(snapshot.authorization_path)
                )
            except (TypeError, ValueError):
                _deny("unknown_authorization_path")

            if not isinstance(runtime, EnterpriseAuthorizationRuntime):
                _deny("enterprise_authorization_runtime_unavailable")
            if not callable(runtime.audit_sink):
                _deny("durable_audit_sink_unavailable")

            if path is AuthorizationPath.MEMBERSHIP:
                role = _validate_membership_snapshot(snapshot)
                _require_authoritative_state(
                    runtime,
                    snapshot,
                    operation,
                    path,
                    now_epoch=decision_time,
                )
                if not _role_allows(role, policy):
                    _deny("role_permission_denied")
                if policy.step_up_required:
                    _require_step_up(snapshot, now_epoch=decision_time)
            elif path is AuthorizationPath.TEMPORARY_GRANT:
                _validate_temporary_grant(snapshot, policy, now_epoch=decision_time)
                _require_authoritative_state(
                    runtime,
                    snapshot,
                    operation,
                    path,
                    now_epoch=decision_time,
                )
            else:  # pragma: no cover - enum exhaustiveness guard
                _deny("unknown_authorization_path")
            resolved_audit_references = _resolve_audit_references(
                runtime,
                auth,
                operation,
            )
        else:
            _deny("unsupported_principal_type")
    except AppError as error:
        _emit_deny(
            auth,
            policy,
            reason=getattr(error, "authorization_reason", "authorization_denied"),
            now_epoch=decision_time,
            audit_sink=(
                runtime.audit_sink
                if principal_type == "user"
                and isinstance(runtime, EnterpriseAuthorizationRuntime)
                and callable(runtime.audit_sink)
                else audit_sink
            ),
        )
        raise

    _emit_allow(
        auth,
        policy,
        now_epoch=decision_time,
        audit_sink=(
            runtime.audit_sink
            if getattr(auth, "principal_type", None) == "user"
            and isinstance(runtime, EnterpriseAuthorizationRuntime)
            else audit_sink
        ),
        durable_receipt_required=getattr(auth, "principal_type", None) == "user",
        audit_references=resolved_audit_references,
    )
    return auth


def operation_policy(operation_id: OperationId | str) -> OperationPolicy:
    """Return a closed policy or deny; never infer from an HTTP method."""
    operation = _coerce_operation(operation_id)
    policy = OPERATION_POLICIES.get(operation)
    if policy is None:
        _deny("unmapped_operation")
    return policy
