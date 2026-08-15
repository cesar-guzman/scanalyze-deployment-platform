"""Closed provider contracts for the repository-only GUG-377 materializer.

This module is deliberately SDK-free and performs no filesystem, subprocess,
credential, provider, or network operations.  It exposes only two checked-in
adapter implementations: an inert fail-closed default and a deterministic
scripted adapter for repository tests.  The future live-provider construction
boundary remains an unconditional stop.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import re
from typing import Any, Mapping, Protocol, final, runtime_checkable

from tooling.platform_authority_gug365_upstream_prerequisites import (
    canonical_digest,
)


STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED = (
    "STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED"
)

_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATION_ID = re.compile(
    r"^GUG377_OP_(?:0[1-9]|[12][0-9]|30)_[A-Z][A-Z0-9_]+$"
)


class ProviderContractError(ValueError):
    """Stable provider-contract error that never contains caller data."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if isinstance(code, str) and _TOKEN.fullmatch(code)
            else "PROVIDER_CONTRACT_INVALID"
        )
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise ProviderContractError(code)


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


class ProviderStatus(str, Enum):
    """Closed normalized status set accepted from a provider adapter."""

    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class ReconciliationStatus(str, Enum):
    """Closed read-only reconciliation conclusions."""

    EFFECT_PROVEN = "EFFECT_PROVEN"
    NO_EFFECT_PROVEN = "NO_EFFECT_PROVEN"
    INCONCLUSIVE = "INCONCLUSIVE"


class OperationKind(str, Enum):
    """The exact ordered GUG-377 write set; callers cannot add operations."""

    CREATE_APPLICATION = "CREATE_APPLICATION"
    PUT_APPLICATION_GRANT = "PUT_APPLICATION_GRANT"
    PUT_APPLICATION_ACCESS_SCOPE = "PUT_APPLICATION_ACCESS_SCOPE"
    PUT_APPLICATION_ASSIGNMENT_CONFIG = "PUT_APPLICATION_ASSIGNMENT_CONFIG"
    CREATE_APPLICATION_ASSIGNMENT = "CREATE_APPLICATION_ASSIGNMENT"
    CLASSIFIER_CREATE_PERMISSION_SET = "CLASSIFIER_CREATE_PERMISSION_SET"
    APPROVER_CREATE_PERMISSION_SET = "APPROVER_CREATE_PERMISSION_SET"
    CLASSIFIER_PUT_INLINE_POLICY = "CLASSIFIER_PUT_INLINE_POLICY"
    APPROVER_PUT_INLINE_POLICY = "APPROVER_PUT_INLINE_POLICY"
    CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT = (
        "CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT"
    )
    APPROVER_CREATE_ACCOUNT_ASSIGNMENT = (
        "APPROVER_CREATE_ACCOUNT_ASSIGNMENT"
    )
    CLASSIFIER_PROVISION_PERMISSION_SET = (
        "CLASSIFIER_PROVISION_PERMISSION_SET"
    )
    APPROVER_PROVISION_PERMISSION_SET = (
        "APPROVER_PROVISION_PERMISSION_SET"
    )
    PUT_APPLICATION_AUTH_METHOD = "PUT_APPLICATION_AUTH_METHOD"
    CREATE_KMS_KEY = "CREATE_KMS_KEY"
    ENABLE_KMS_KEY_ROTATION = "ENABLE_KMS_KEY_ROTATION"
    CREATE_KMS_ALIAS = "CREATE_KMS_ALIAS"
    CREATE_ARTIFACT_BUCKET = "CREATE_ARTIFACT_BUCKET"
    PUT_BUCKET_OWNERSHIP_CONTROLS = "PUT_BUCKET_OWNERSHIP_CONTROLS"
    PUT_BUCKET_PUBLIC_ACCESS_BLOCK = "PUT_BUCKET_PUBLIC_ACCESS_BLOCK"
    PUT_BUCKET_VERSIONING = "PUT_BUCKET_VERSIONING"
    PUT_BUCKET_ENCRYPTION = "PUT_BUCKET_ENCRYPTION"
    PUT_BUCKET_POLICY = "PUT_BUCKET_POLICY"
    PUT_BUCKET_TAGGING = "PUT_BUCKET_TAGGING"
    PUT_SIGNING_PROFILE = "PUT_SIGNING_PROFILE"
    CREATE_CODE_SIGNING_CONFIG = "CREATE_CODE_SIGNING_CONFIG"
    BROKER_PUT_UNSIGNED_OBJECT = "BROKER_PUT_UNSIGNED_OBJECT"
    BROKER_START_SIGNING_JOB = "BROKER_START_SIGNING_JOB"
    LEDGER_FACTORY_PUT_UNSIGNED_OBJECT = (
        "LEDGER_FACTORY_PUT_UNSIGNED_OBJECT"
    )
    LEDGER_FACTORY_START_SIGNING_JOB = (
        "LEDGER_FACTORY_START_SIGNING_JOB"
    )


@dataclass(frozen=True, slots=True)
class OperationDefinition:
    """One immutable operation identity and its reviewed provider action."""

    kind: OperationKind
    operation_id: str
    action: str


OPERATION_DEFINITIONS = (
    OperationDefinition(
        OperationKind.CREATE_APPLICATION,
        "GUG377_OP_01_CREATE_APPLICATION",
        "sso:CreateApplication",
    ),
    OperationDefinition(
        OperationKind.PUT_APPLICATION_GRANT,
        "GUG377_OP_02_PUT_APPLICATION_GRANT",
        "sso:PutApplicationGrant",
    ),
    OperationDefinition(
        OperationKind.PUT_APPLICATION_ACCESS_SCOPE,
        "GUG377_OP_03_PUT_APPLICATION_ACCESS_SCOPE",
        "sso:PutApplicationAccessScope",
    ),
    OperationDefinition(
        OperationKind.PUT_APPLICATION_ASSIGNMENT_CONFIG,
        "GUG377_OP_04_PUT_APPLICATION_ASSIGNMENT_CONFIG",
        "sso:PutApplicationAssignmentConfiguration",
    ),
    OperationDefinition(
        OperationKind.CREATE_APPLICATION_ASSIGNMENT,
        "GUG377_OP_05_CREATE_APPLICATION_ASSIGNMENT",
        "sso:CreateApplicationAssignment",
    ),
    OperationDefinition(
        OperationKind.CLASSIFIER_CREATE_PERMISSION_SET,
        "GUG377_OP_06_CLASSIFIER_CREATE_PERMISSION_SET",
        "sso:CreatePermissionSet",
    ),
    OperationDefinition(
        OperationKind.APPROVER_CREATE_PERMISSION_SET,
        "GUG377_OP_07_APPROVER_CREATE_PERMISSION_SET",
        "sso:CreatePermissionSet",
    ),
    OperationDefinition(
        OperationKind.CLASSIFIER_PUT_INLINE_POLICY,
        "GUG377_OP_08_CLASSIFIER_PUT_INLINE_POLICY",
        "sso:PutInlinePolicyToPermissionSet",
    ),
    OperationDefinition(
        OperationKind.APPROVER_PUT_INLINE_POLICY,
        "GUG377_OP_09_APPROVER_PUT_INLINE_POLICY",
        "sso:PutInlinePolicyToPermissionSet",
    ),
    OperationDefinition(
        OperationKind.CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT,
        "GUG377_OP_10_CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT",
        "sso:CreateAccountAssignment",
    ),
    OperationDefinition(
        OperationKind.APPROVER_CREATE_ACCOUNT_ASSIGNMENT,
        "GUG377_OP_11_APPROVER_CREATE_ACCOUNT_ASSIGNMENT",
        "sso:CreateAccountAssignment",
    ),
    OperationDefinition(
        OperationKind.CLASSIFIER_PROVISION_PERMISSION_SET,
        "GUG377_OP_12_CLASSIFIER_PROVISION_PERMISSION_SET",
        "sso:ProvisionPermissionSet",
    ),
    OperationDefinition(
        OperationKind.APPROVER_PROVISION_PERMISSION_SET,
        "GUG377_OP_13_APPROVER_PROVISION_PERMISSION_SET",
        "sso:ProvisionPermissionSet",
    ),
    OperationDefinition(
        OperationKind.PUT_APPLICATION_AUTH_METHOD,
        "GUG377_OP_14_PUT_APPLICATION_AUTH_METHOD",
        "sso:PutApplicationAuthenticationMethod",
    ),
    OperationDefinition(
        OperationKind.CREATE_KMS_KEY,
        "GUG377_OP_15_CREATE_KMS_KEY",
        "kms:CreateKey",
    ),
    OperationDefinition(
        OperationKind.ENABLE_KMS_KEY_ROTATION,
        "GUG377_OP_16_ENABLE_KMS_KEY_ROTATION",
        "kms:EnableKeyRotation",
    ),
    OperationDefinition(
        OperationKind.CREATE_KMS_ALIAS,
        "GUG377_OP_17_CREATE_KMS_ALIAS",
        "kms:CreateAlias",
    ),
    OperationDefinition(
        OperationKind.CREATE_ARTIFACT_BUCKET,
        "GUG377_OP_18_CREATE_ARTIFACT_BUCKET",
        "s3:CreateBucket",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_OWNERSHIP_CONTROLS,
        "GUG377_OP_19_PUT_BUCKET_OWNERSHIP_CONTROLS",
        "s3:PutBucketOwnershipControls",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_PUBLIC_ACCESS_BLOCK,
        "GUG377_OP_20_PUT_BUCKET_PUBLIC_ACCESS_BLOCK",
        "s3:PutPublicAccessBlock",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_VERSIONING,
        "GUG377_OP_21_PUT_BUCKET_VERSIONING",
        "s3:PutBucketVersioning",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_ENCRYPTION,
        "GUG377_OP_22_PUT_BUCKET_ENCRYPTION",
        "s3:PutBucketEncryption",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_POLICY,
        "GUG377_OP_23_PUT_BUCKET_POLICY",
        "s3:PutBucketPolicy",
    ),
    OperationDefinition(
        OperationKind.PUT_BUCKET_TAGGING,
        "GUG377_OP_24_PUT_BUCKET_TAGGING",
        "s3:PutBucketTagging",
    ),
    OperationDefinition(
        OperationKind.PUT_SIGNING_PROFILE,
        "GUG377_OP_25_PUT_SIGNING_PROFILE",
        "signer:PutSigningProfile",
    ),
    OperationDefinition(
        OperationKind.CREATE_CODE_SIGNING_CONFIG,
        "GUG377_OP_26_CREATE_CODE_SIGNING_CONFIG",
        "lambda:CreateCodeSigningConfig",
    ),
    OperationDefinition(
        OperationKind.BROKER_PUT_UNSIGNED_OBJECT,
        "GUG377_OP_27_BROKER_PUT_UNSIGNED_OBJECT",
        "s3:PutObject",
    ),
    OperationDefinition(
        OperationKind.BROKER_START_SIGNING_JOB,
        "GUG377_OP_28_BROKER_START_SIGNING_JOB",
        "signer:StartSigningJob",
    ),
    OperationDefinition(
        OperationKind.LEDGER_FACTORY_PUT_UNSIGNED_OBJECT,
        "GUG377_OP_29_LEDGER_FACTORY_PUT_UNSIGNED_OBJECT",
        "s3:PutObject",
    ),
    OperationDefinition(
        OperationKind.LEDGER_FACTORY_START_SIGNING_JOB,
        "GUG377_OP_30_LEDGER_FACTORY_START_SIGNING_JOB",
        "signer:StartSigningJob",
    ),
)

if len(OperationKind) != 30 or tuple(item.kind for item in OPERATION_DEFINITIONS) != tuple(
    OperationKind
):  # pragma: no cover - import-time invariant
    raise RuntimeError("PROVIDER_OPERATION_CATALOG_INVALID")

_DEFINITION_BY_KIND = {item.kind: item for item in OPERATION_DEFINITIONS}
_DEFINITION_BY_ID = {item.operation_id: item for item in OPERATION_DEFINITIONS}


@dataclass(frozen=True, slots=True)
class ProviderOperation:
    """Exact causal operation passed to a typed provider adapter."""

    global_sequence: int
    operation_id: str
    operation_kind: OperationKind
    action: str
    resource_kind: str
    dependencies: tuple[str, ...]
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    polling_kind: str
    produced_slots: tuple[str, ...]
    consumed_slots: tuple[str, ...]
    consumed_slot_bindings: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class BeforeStateProjection:
    """Digest-only provider before-state projection."""

    operation_id: str
    operation_kind: OperationKind
    resource_kind: str
    classification: str
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    projection_digest: str


@dataclass(frozen=True, slots=True)
class ProviderSlotProjection:
    """Digest-only output slot from one exact successful operation."""

    slot: str
    producer_operation_id: str
    producer_operation_kind: OperationKind
    value_projection_digest: str
    projection_digest: str


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """Digest-only provider result bound to one exact causal operation."""

    operation_id: str
    operation_kind: OperationKind
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    status: ProviderStatus
    result_projection_digest: str
    readback_projection_digest: str
    consumed_slot_binding_digest: str
    produced_slot_projections: tuple[ProviderSlotProjection, ...]


@dataclass(frozen=True, slots=True)
class ReconciliationProjection:
    """Read-only reconciliation result for an already-consumed attempt."""

    operation_id: str
    operation_kind: OperationKind
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    status: ReconciliationStatus
    readback_projection_digest: str
    consumed_slot_binding_digest: str
    projection_digest: str
    reconciliation_digest: str
    read_only: bool
    provider_writes: int


def operation_from_record(record: Mapping[str, Any]) -> ProviderOperation:
    """Convert one closed plan record into its immutable adapter value."""

    if not isinstance(record, Mapping):
        _fail("PROVIDER_OPERATION_INVALID")
    try:
        kind = OperationKind(record.get("operation_kind"))
    except (TypeError, ValueError):
        _fail("PROVIDER_OPERATION_KIND_INVALID")
    definition = _DEFINITION_BY_KIND[kind]
    operation_id = record.get("operation_id")
    action = record.get("action")
    sequence = record.get("global_sequence")
    dependencies = record.get("dependencies")
    polling_policy = record.get("polling_policy")
    if (
        not isinstance(operation_id, str)
        or _OPERATION_ID.fullmatch(operation_id) is None
        or operation_id != definition.operation_id
        or action != definition.action
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence != tuple(OperationKind).index(kind) + 1
        or not isinstance(dependencies, list)
        or not all(
            isinstance(item, str) and _OPERATION_ID.fullmatch(item)
            for item in dependencies
        )
        or not isinstance(polling_policy, Mapping)
        or not isinstance(polling_policy.get("kind"), str)
        or not polling_policy["kind"]
    ):
        _fail("PROVIDER_OPERATION_BINDING_INVALID")
    expected_dependencies = (
        ()
        if sequence == 1
        else (OPERATION_DEFINITIONS[sequence - 2].operation_id,)
    )
    if tuple(dependencies) != expected_dependencies:
        _fail("PROVIDER_OPERATION_DEPENDENCY_INVALID")
    resource_kind = record.get("inventory_resource")
    if not isinstance(resource_kind, str) or not resource_kind:
        _fail("PROVIDER_RESOURCE_KIND_INVALID")
    produced_slots = record.get("produced_slots")
    consumed_slots = record.get("consumed_slots")
    if (
        not isinstance(produced_slots, list)
        or not isinstance(consumed_slots, list)
        or len(set(produced_slots)) != len(produced_slots)
        or len(set(consumed_slots)) != len(consumed_slots)
        or not all(isinstance(slot, str) and _TOKEN.fullmatch(slot) for slot in produced_slots)
        or not all(isinstance(slot, str) and _TOKEN.fullmatch(slot) for slot in consumed_slots)
    ):
        _fail("PROVIDER_OPERATION_SLOTS_INVALID")
    return ProviderOperation(
        global_sequence=sequence,
        operation_id=operation_id,
        operation_kind=kind,
        action=action,
        resource_kind=resource_kind,
        dependencies=tuple(dependencies),
        request_digest=_require_digest(
            record.get("request_contract_digest"),
            "PROVIDER_REQUEST_DIGEST_INVALID",
        ),
        before_state_digest=_require_digest(
            record.get("before_state_digest"),
            "PROVIDER_BEFORE_STATE_DIGEST_INVALID",
        ),
        target_state_digest=_require_digest(
            record.get("target_state_digest"),
            "PROVIDER_TARGET_STATE_DIGEST_INVALID",
        ),
        polling_kind=polling_policy["kind"],
        produced_slots=tuple(produced_slots),
        consumed_slots=tuple(consumed_slots),
        consumed_slot_bindings=(),
    )


def bind_consumed_slot_projections(
    operation: ProviderOperation, slot_projections: Mapping[str, str]
) -> ProviderOperation:
    """Resolve only the exact prior slot projections required by an operation."""

    if not isinstance(operation, ProviderOperation) or not isinstance(
        slot_projections, Mapping
    ):
        _fail("PROVIDER_SLOT_BINDING_INVALID")
    bindings: list[tuple[str, str]] = []
    for slot in operation.consumed_slots:
        projection_digest = slot_projections.get(slot)
        bindings.append(
            (
                slot,
                _require_digest(
                    projection_digest, "PROVIDER_SLOT_PROJECTION_DIGEST_INVALID"
                ),
            )
        )
    return replace(operation, consumed_slot_bindings=tuple(bindings))


@runtime_checkable
class ProviderAdapter(Protocol):
    """Typed closed adapter boundary used by the repository materializer."""

    @property
    def mode(self) -> str: ...

    def observe_before_state(
        self, operation: ProviderOperation
    ) -> BeforeStateProjection: ...

    def mutate_once(self, operation: ProviderOperation) -> ProviderResult: ...

    def poll(self, operation: ProviderOperation) -> ProviderResult: ...

    def reconcile_read_only(
        self, operation: ProviderOperation
    ) -> ReconciliationProjection: ...


@final
@dataclass(frozen=True, slots=True)
class InertProviderAdapter:
    """Default adapter; every entry point stops before any external effect."""

    mode: str = field(default="INERT_DEFAULT", init=False)

    def observe_before_state(
        self, operation: ProviderOperation
    ) -> BeforeStateProjection:
        del operation
        _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)

    def mutate_once(self, operation: ProviderOperation) -> ProviderResult:
        del operation
        _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)

    def poll(self, operation: ProviderOperation) -> ProviderResult:
        del operation
        _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)

    def reconcile_read_only(
        self, operation: ProviderOperation
    ) -> ReconciliationProjection:
        del operation
        _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)


def _before_state_projection(operation: ProviderOperation) -> BeforeStateProjection:
    projection_digest = canonical_digest(
        {
            "operation_id": operation.operation_id,
            "operation_kind": operation.operation_kind.value,
            "resource_kind": operation.resource_kind,
            "classification": "SCRIPTED_SYNTHETIC",
            "request_digest": operation.request_digest,
            "before_state_digest": operation.before_state_digest,
            "target_state_digest": operation.target_state_digest,
        }
    )
    return BeforeStateProjection(
        operation_id=operation.operation_id,
        operation_kind=operation.operation_kind,
        resource_kind=operation.resource_kind,
        classification="SCRIPTED_SYNTHETIC",
        request_digest=operation.request_digest,
        before_state_digest=operation.before_state_digest,
        target_state_digest=operation.target_state_digest,
        projection_digest=projection_digest,
    )


def consumed_slot_binding_digest(operation: ProviderOperation) -> str:
    """Bind exact prior output projections into the next causal operation."""

    if not isinstance(operation, ProviderOperation) or tuple(
        slot for slot, _digest in operation.consumed_slot_bindings
    ) != operation.consumed_slots:
        _fail("PROVIDER_CONSUMED_SLOT_BINDING_MISMATCH")
    bindings: list[dict[str, str]] = []
    for slot, projection_digest in operation.consumed_slot_bindings:
        bindings.append(
            {
                "slot": slot,
                "projection_digest": _require_digest(
                    projection_digest, "PROVIDER_SLOT_PROJECTION_DIGEST_INVALID"
                ),
            }
        )
    return canonical_digest(
        {
            "domain": "GUG377_CONSUMED_SLOT_BINDINGS_V1",
            "operation_id": operation.operation_id,
            "request_digest": operation.request_digest,
            "bindings": bindings,
        }
    )


def provider_result_projection_digest(
    operation: ProviderOperation, status: ProviderStatus
) -> str:
    """Bind one normalized result status to the exact causal request."""

    if not isinstance(operation, ProviderOperation) or not isinstance(
        status, ProviderStatus
    ):
        _fail("PROVIDER_RESULT_BINDING_INVALID")
    return canonical_digest(
        {
            "operation_id": operation.operation_id,
            "operation_kind": operation.operation_kind.value,
            "request_digest": operation.request_digest,
            "before_state_digest": operation.before_state_digest,
            "target_state_digest": operation.target_state_digest,
            "status": status.value,
            "consumed_slot_binding_digest": consumed_slot_binding_digest(operation),
            "produced_slots": list(operation.produced_slots),
        }
    )


def provider_slot_projections(
    operation: ProviderOperation,
    status: ProviderStatus,
    result_projection_digest: str,
) -> tuple[ProviderSlotProjection, ...]:
    """Project successful fake outputs as causal digests, never provider values."""

    if status is not ProviderStatus.SUCCEEDED:
        return ()
    result_digest = _require_digest(
        result_projection_digest, "PROVIDER_RESULT_PROJECTION_DIGEST_INVALID"
    )
    binding_digest = consumed_slot_binding_digest(operation)
    return tuple(
        _scripted_slot_projection(
            operation=operation,
            slot=slot,
            result_projection_digest=result_digest,
            consumed_binding_digest=binding_digest,
        )
        for slot in operation.produced_slots
    )


def _scripted_slot_projection(
    *,
    operation: ProviderOperation,
    slot: str,
    result_projection_digest: str,
    consumed_binding_digest: str,
) -> ProviderSlotProjection:
    value_projection_digest = canonical_digest(
        {
            "domain": "GUG377_SCRIPTED_PROVIDER_VALUE_PROJECTION_V1",
            "slot": slot,
            "producer_operation_id": operation.operation_id,
            "producer_operation_kind": operation.operation_kind.value,
            "request_digest": operation.request_digest,
        }
    )
    projection_digest = canonical_digest(
        {
            "domain": "GUG377_PROVIDER_SLOT_PROJECTION_V1",
            "slot": slot,
            "producer_operation_id": operation.operation_id,
            "producer_operation_kind": operation.operation_kind.value,
            "request_digest": operation.request_digest,
            "before_state_digest": operation.before_state_digest,
            "target_state_digest": operation.target_state_digest,
            "result_projection_digest": result_projection_digest,
            "consumed_slot_binding_digest": consumed_binding_digest,
            "value_projection_digest": value_projection_digest,
        }
    )
    return ProviderSlotProjection(
        slot=slot,
        producer_operation_id=operation.operation_id,
        producer_operation_kind=operation.operation_kind,
        value_projection_digest=value_projection_digest,
        projection_digest=projection_digest,
    )


def _provider_result(
    operation: ProviderOperation, status: ProviderStatus
) -> ProviderResult:
    result_projection_digest = provider_result_projection_digest(operation, status)
    readback_projection_digest = canonical_digest(
        {
            "operation_id": operation.operation_id,
            "target_state_digest": operation.target_state_digest,
        }
    )
    binding_digest = consumed_slot_binding_digest(operation)
    return ProviderResult(
        operation_id=operation.operation_id,
        operation_kind=operation.operation_kind,
        request_digest=operation.request_digest,
        before_state_digest=operation.before_state_digest,
        target_state_digest=operation.target_state_digest,
        status=status,
        result_projection_digest=result_projection_digest,
        readback_projection_digest=readback_projection_digest,
        consumed_slot_binding_digest=binding_digest,
        produced_slot_projections=provider_slot_projections(
            operation, status, result_projection_digest
        ),
    )


def _reconciliation_projection(
    operation: ProviderOperation, status: ReconciliationStatus
) -> ReconciliationProjection:
    if status is ReconciliationStatus.EFFECT_PROVEN:
        readback_projection_digest = operation.target_state_digest
    elif status is ReconciliationStatus.NO_EFFECT_PROVEN:
        readback_projection_digest = operation.before_state_digest
    else:
        readback_projection_digest = canonical_digest(
            {
                "domain": "GUG377_RECONCILIATION_INCONCLUSIVE_V1",
                "operation_id": operation.operation_id,
                "request_digest": operation.request_digest,
            }
        )
    binding_digest = consumed_slot_binding_digest(operation)
    material = {
        "operation_id": operation.operation_id,
        "operation_kind": operation.operation_kind.value,
        "request_digest": operation.request_digest,
        "before_state_digest": operation.before_state_digest,
        "target_state_digest": operation.target_state_digest,
        "status": status.value,
        "readback_projection_digest": readback_projection_digest,
        "consumed_slot_binding_digest": binding_digest,
        "read_only": True,
        "provider_writes": 0,
    }
    projection_digest = canonical_digest(material)
    return ReconciliationProjection(
        operation_id=operation.operation_id,
        operation_kind=operation.operation_kind,
        request_digest=operation.request_digest,
        before_state_digest=operation.before_state_digest,
        target_state_digest=operation.target_state_digest,
        status=status,
        readback_projection_digest=readback_projection_digest,
        consumed_slot_binding_digest=binding_digest,
        projection_digest=projection_digest,
        reconciliation_digest=projection_digest,
        read_only=True,
        provider_writes=0,
    )


_PROVIDER_RESULT_FIELDS = frozenset(
    {
        "operation_id",
        "operation_kind",
        "request_digest",
        "before_state_digest",
        "target_state_digest",
        "status",
        "result_projection_digest",
        "readback_projection_digest",
        "consumed_slot_binding_digest",
        "produced_slot_projections",
    }
)


@final
@dataclass(frozen=True)
class ScriptedProviderAdapter:
    """Deterministic in-memory adapter for synthetic repository execution."""

    _operations: Mapping[str, ProviderOperation]
    mode: str = field(default="SCRIPTED_TEST", init=False)
    write_calls: list[str] = field(default_factory=list, init=False, compare=False)
    poll_calls: list[str] = field(default_factory=list, init=False, compare=False)
    reconcile_calls: list[str] = field(
        default_factory=list, init=False, compare=False
    )
    _substitutions: dict[str, dict[str, object]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _ambiguous_operations: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    _poll_scripts: dict[str, tuple[ProviderStatus, ...]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _poll_offsets: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _reconciliations: dict[str, ReconciliationStatus] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    @classmethod
    def succeeding(cls, plan: Mapping[str, Any]) -> ScriptedProviderAdapter:
        """Build a complete success script for one exact repository plan."""

        if cls is not ScriptedProviderAdapter:
            _fail("ADAPTER_SUBCLASS_FORBIDDEN")
        if not isinstance(plan, Mapping):
            _fail("PROVIDER_SCRIPT_PLAN_INVALID")
        supplied = plan.get("operations")
        if not isinstance(supplied, list) or len(supplied) != len(
            OPERATION_DEFINITIONS
        ):
            _fail("PROVIDER_SCRIPT_OPERATION_SET_INVALID")
        operations = [operation_from_record(record) for record in supplied]
        if tuple(operation.operation_kind for operation in operations) != tuple(
            OperationKind
        ) or tuple(operation.operation_id for operation in operations) != tuple(
            item.operation_id for item in OPERATION_DEFINITIONS
        ):
            _fail("PROVIDER_SCRIPT_OPERATION_ORDER_INVALID")
        adapter = ScriptedProviderAdapter(
            _operations={operation.operation_id: operation for operation in operations}
        )
        for operation in operations:
            if operation.polling_kind != "NONE":
                adapter._poll_scripts[operation.operation_id] = (
                    ProviderStatus.SUCCEEDED,
                )
        return adapter

    def _operation(self, operation_id: str) -> ProviderOperation:
        if not isinstance(operation_id, str) or operation_id not in self._operations:
            _fail("PROVIDER_OPERATION_UNKNOWN")
        return self._operations[operation_id]

    def _require_exact_operation(
        self,
        operation: ProviderOperation,
        *,
        require_consumed_bindings: bool = True,
    ) -> ProviderOperation:
        if not isinstance(operation, ProviderOperation):
            _fail("PROVIDER_OPERATION_INVALID")
        expected = self._operation(operation.operation_id)
        unresolved = replace(operation, consumed_slot_bindings=())
        if unresolved != expected:
            _fail("PROVIDER_OPERATION_BINDING_MISMATCH")
        if require_consumed_bindings:
            consumed_slot_binding_digest(operation)
        return operation

    def observe_before_state(
        self, operation: ProviderOperation
    ) -> BeforeStateProjection:
        return _before_state_projection(
            self._require_exact_operation(
                operation, require_consumed_bindings=False
            )
        )

    def mutate_once(self, operation: ProviderOperation) -> ProviderResult:
        expected = self._require_exact_operation(operation)
        if expected.operation_id in self.write_calls:
            _fail("PROVIDER_WRITE_REPLAY_FORBIDDEN")
        self.write_calls.append(expected.operation_id)
        if expected.operation_id in self._ambiguous_operations:
            _fail("PROVIDER_OUTCOME_AMBIGUOUS")
        status = (
            ProviderStatus.SUCCEEDED
            if expected.polling_kind == "NONE"
            else ProviderStatus.IN_PROGRESS
        )
        result = _provider_result(expected, status)
        substitutions = self._substitutions.get(expected.operation_id, {})
        if substitutions:
            try:
                result = replace(result, **substitutions)
            except (TypeError, ValueError):
                _fail("PROVIDER_RESULT_SUBSTITUTION_INVALID")
        return result

    def poll(self, operation: ProviderOperation) -> ProviderResult:
        expected = self._require_exact_operation(operation)
        if expected.polling_kind == "NONE":
            _fail("PROVIDER_POLL_NOT_ALLOWED")
        self.poll_calls.append(expected.operation_id)
        script = self._poll_scripts.get(expected.operation_id)
        if not script:
            _fail("PROVIDER_POLL_SCRIPT_MISSING")
        offset = self._poll_offsets.get(expected.operation_id, 0)
        status = script[min(offset, len(script) - 1)]
        self._poll_offsets[expected.operation_id] = offset + 1
        result = _provider_result(expected, status)
        substitutions = self._substitutions.get(expected.operation_id, {})
        if substitutions:
            try:
                result = replace(result, **substitutions)
            except (TypeError, ValueError):
                _fail("PROVIDER_RESULT_SUBSTITUTION_INVALID")
        return result

    def reconcile_read_only(
        self, operation: ProviderOperation
    ) -> ReconciliationProjection:
        expected = self._require_exact_operation(operation)
        self.reconcile_calls.append(expected.operation_id)
        status = self._reconciliations.get(
            expected.operation_id, ReconciliationStatus.INCONCLUSIVE
        )
        return _reconciliation_projection(expected, status)

    def substitute_result(
        self, scripted_operation_id: str, **bindings: object
    ) -> None:
        """Replace selected synthetic result fields for an adversarial test."""

        self._operation(scripted_operation_id)
        if not bindings or not set(bindings).issubset(_PROVIDER_RESULT_FIELDS):
            _fail("PROVIDER_RESULT_SUBSTITUTION_INVALID")
        self._substitutions.setdefault(scripted_operation_id, {}).update(bindings)

    def make_ambiguous(self, operation_id: str) -> None:
        self._operation(operation_id)
        self._ambiguous_operations.add(operation_id)

    def set_poll_script(
        self, operation_id: str, statuses: tuple[ProviderStatus, ...]
    ) -> None:
        operation = self._operation(operation_id)
        if (
            operation.polling_kind == "NONE"
            or not isinstance(statuses, tuple)
            or not statuses
            or not all(isinstance(status, ProviderStatus) for status in statuses)
        ):
            _fail("PROVIDER_POLL_SCRIPT_INVALID")
        self._poll_scripts[operation_id] = statuses
        self._poll_offsets[operation_id] = 0

    def set_reconciliation(
        self, operation_id: str, status: ReconciliationStatus
    ) -> None:
        self._operation(operation_id)
        if not isinstance(status, ReconciliationStatus):
            _fail("PROVIDER_RECONCILIATION_STATUS_INVALID")
        self._reconciliations[operation_id] = status


def build_live_provider_adapter(*_args: object, **_kwargs: object) -> ProviderAdapter:
    """Future live-provider boundary; deliberately unavailable in GUG-377."""

    _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)
    raise AssertionError("unreachable")
