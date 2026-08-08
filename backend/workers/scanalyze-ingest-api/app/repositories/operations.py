"""Durable idempotency ledger for the versioned document journey.

The ledger deliberately shares the existing documents DynamoDB table.  Its
keys are disjoint from document records and are derived only from an owner
binding, the contract/operation, and already-digested actor/idempotency values.
Raw idempotency keys, request bodies, identity subjects, object locations, and
ephemeral upload capabilities never cross this persistence boundary.

There is no DynamoDB TTL attribute on these records.  ``expires_at`` is a
logical contract deadline; transitioning to ``EXPIRED`` retains the evidence
indefinitely for reconciliation and audit.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, TypeAlias


OPERATION_SCHEMA_VERSION = "scanalyze.document-journey-operation.v1"
_CONDITIONAL_FAILURE = "ConditionalCheckFailedException"
_DIGEST_PATTERN = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_FAILURE_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SCHEMA_VERSION_PATTERN = re.compile(r"^[a-z][a-z0-9.-]{2,127}$")
_STATUS_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_CONTENT_TYPE_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$"
)
_RESOURCE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_MAX_DURABLE_RESPONSE_BYTES = 2_048
_MAX_SCALAR_STRING_LENGTH = 512
_DOCUMENT_CONTENT_TYPES = frozenset(
    {"application/pdf", "image/jpeg", "image/png", "image/tiff"}
)
_OPERATION_RESOURCE_TYPES = {
    "batches.create": "batch",
    "documents.create": "document",
}

_DURABLE_RESPONSE_FIELDS = {
    "batch": frozenset(
        {
            "schemaVersion",
            "contractVersion",
            "operation",
            "batchId",
            "status",
            "createdAt",
        }
    ),
    "document": frozenset(
        {
            "schemaVersion",
            "contractVersion",
            "operation",
            "documentId",
            "batchId",
            "status",
            "createdAt",
            "contentType",
        }
    ),
}
_DURABLE_RESPONSE_REQUIRED_FIELDS = {
    "batch": _DURABLE_RESPONSE_FIELDS["batch"],
    "document": _DURABLE_RESPONSE_FIELDS["document"] - {"batchId"},
}
_FORBIDDEN_RESPONSE_FIELD_FRAGMENTS = frozenset(
    {
        "authorization",
        "body",
        "bucket",
        "capability",
        "cookie",
        "customer",
        "deployment",
        "filename",
        "header",
        "idempotency",
        "metadata",
        "objectkey",
        "payload",
        "presigned",
        "secret",
        "storagekey",
        "subject",
        "token",
        "upload",
        "uri",
        "url",
    }
)

DurableScalar: TypeAlias = str | int | float | bool | None


class OperationState(str, Enum):
    """Closed persistence states for one idempotent operation."""

    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_TERMINAL = "FAILED_TERMINAL"
    UNKNOWN_OR_QUARANTINED = "UNKNOWN_OR_QUARANTINED"
    EXPIRED = "EXPIRED"


_ALLOWED_TRANSITIONS = {
    OperationState.PENDING: frozenset(
        {
            OperationState.SUCCEEDED,
            OperationState.FAILED_RETRYABLE,
            OperationState.FAILED_TERMINAL,
            OperationState.UNKNOWN_OR_QUARANTINED,
            OperationState.EXPIRED,
        }
    ),
    OperationState.FAILED_RETRYABLE: frozenset(
        {
            OperationState.PENDING,
            OperationState.FAILED_TERMINAL,
            OperationState.UNKNOWN_OR_QUARANTINED,
            OperationState.EXPIRED,
        }
    ),
    OperationState.SUCCEEDED: frozenset({OperationState.EXPIRED}),
    OperationState.FAILED_TERMINAL: frozenset({OperationState.EXPIRED}),
    OperationState.UNKNOWN_OR_QUARANTINED: frozenset({OperationState.EXPIRED}),
    OperationState.EXPIRED: frozenset(),
}
_FAILURE_STATES = frozenset(
    {
        OperationState.FAILED_RETRYABLE,
        OperationState.FAILED_TERMINAL,
        OperationState.UNKNOWN_OR_QUARANTINED,
    }
)
_COMPLETED_STATES = frozenset(
    {
        OperationState.SUCCEEDED,
        OperationState.FAILED_TERMINAL,
        OperationState.UNKNOWN_OR_QUARANTINED,
        OperationState.EXPIRED,
    }
)


class OperationRepositoryError(RuntimeError):
    """Base class for fail-closed ledger errors with no provider details."""

    def __init__(self, message: str = "operation ledger rejected") -> None:
        super().__init__(message)


class OperationContractError(OperationRepositoryError):
    """The caller or persisted record violates the closed ledger contract."""


class OperationConflict(OperationRepositoryError):
    """The key is already bound to another request or CAS transition."""


class OperationPersistenceAmbiguous(OperationRepositoryError):
    """A write outcome could not be proven with a strong consistent read."""


@dataclass(frozen=True)
class OperationIdentity:
    """Owner-scoped identity containing digests, never a raw idempotency key."""

    contract_version: str
    operation: str
    actor_digest: str
    customer_id: str
    deployment_id: str
    key_digest: str

    def __post_init__(self) -> None:
        for value in (self.contract_version, self.customer_id, self.deployment_id):
            _validated_identifier(value)
        operation = (
            self.operation.value if isinstance(self.operation, Enum) else self.operation
        )
        if (
            not isinstance(operation, str)
            or operation not in _OPERATION_RESOURCE_TYPES
        ):
            raise OperationContractError()
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "actor_digest", _normalized_digest(self.actor_digest))
        object.__setattr__(self, "key_digest", _normalized_digest(self.key_digest))


@dataclass(frozen=True)
class OperationRecord:
    schema_version: str
    contract_version: str
    operation: str
    actor_digest: str
    customer_id: str
    deployment_id: str
    key_digest: str
    request_digest: str
    resource_type: str
    resource_id: str
    durable_response: Mapping[str, DurableScalar]
    state: OperationState
    version: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    completed_at: datetime | None = None
    failure_code: str | None = None

    @property
    def identity(self) -> OperationIdentity:
        return OperationIdentity(
            contract_version=self.contract_version,
            operation=self.operation,
            actor_digest=self.actor_digest,
            customer_id=self.customer_id,
            deployment_id=self.deployment_id,
            key_digest=self.key_digest,
        )


@dataclass(frozen=True)
class ReservationOutcome:
    record: OperationRecord
    created_here: bool


def _validated_identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise OperationContractError()
    return value


def _validated_resource_id(value: object) -> str:
    if not isinstance(value, str) or _RESOURCE_ID_PATTERN.fullmatch(value) is None:
        raise OperationContractError()
    return value


def _normalized_digest(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise OperationContractError()
    digest = value.removeprefix("sha256:")
    return f"sha256:{digest}"


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OperationContractError()
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise OperationContractError()
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise OperationContractError() from error
    return _aware_utc(result)


def _state(value: object) -> OperationState:
    try:
        return value if isinstance(value, OperationState) else OperationState(value)
    except (TypeError, ValueError) as error:
        raise OperationContractError() from error


def _error_code(error: BaseException) -> str | None:
    response = getattr(error, "response", None)
    details = response.get("Error") if isinstance(response, Mapping) else None
    code = details.get("Code") if isinstance(details, Mapping) else None
    return code if isinstance(code, str) else None


def _positive_integer(value: object) -> int:
    try:
        result = int(value)  # DynamoDB resource returns Decimal for numbers.
    except (TypeError, ValueError, OverflowError) as error:
        raise OperationContractError() from error
    if isinstance(value, bool) or result < 1 or str(result) != str(value):
        raise OperationContractError()
    return result


def _operation_key(identity: OperationIdentity) -> dict[str, str]:
    owner_digest = _digest(f"{identity.customer_id}\x1f{identity.deployment_id}")
    contract_digest = _digest(identity.contract_version)
    return {
        "pk": f"GUG354#OWNER#{owner_digest.removeprefix('sha256:')}",
        "sk": (
            f"CONTRACT#{contract_digest.removeprefix('sha256:')}"
            f"#OPERATION#{identity.operation}"
            f"#ACTOR#{identity.actor_digest.removeprefix('sha256:')}"
            f"#KEY#{identity.key_digest.removeprefix('sha256:')}"
        ),
    }


def _normalized_field_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _validate_no_forbidden_response_names(value: object) -> None:
    if isinstance(value, Mapping):
        for raw_name, child in value.items():
            if not isinstance(raw_name, str):
                raise OperationContractError()
            normalized = _normalized_field_name(raw_name)
            if any(fragment in normalized for fragment in _FORBIDDEN_RESPONSE_FIELD_FRAGMENTS):
                raise OperationContractError()
            _validate_no_forbidden_response_names(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_no_forbidden_response_names(child)


def _validated_durable_response(
    value: object,
    *,
    identity: OperationIdentity,
    resource_type: str,
    resource_id: str,
) -> dict[str, DurableScalar]:
    if resource_type not in _DURABLE_RESPONSE_FIELDS or not isinstance(value, Mapping):
        raise OperationContractError()
    _validate_no_forbidden_response_names(value)

    names = set(value)
    allowed = _DURABLE_RESPONSE_FIELDS[resource_type]
    required = _DURABLE_RESPONSE_REQUIRED_FIELDS[resource_type]
    if not required.issubset(names) or not names.issubset(allowed):
        raise OperationContractError()

    result: dict[str, DurableScalar] = {}
    for name, scalar in value.items():
        if scalar is not None and not isinstance(scalar, (str, int, float, bool)):
            raise OperationContractError()
        if isinstance(scalar, str) and len(scalar) > _MAX_SCALAR_STRING_LENGTH:
            raise OperationContractError()
        if isinstance(scalar, float) and not math.isfinite(scalar):
            raise OperationContractError()
        result[str(name)] = scalar

    for name, scalar in result.items():
        if name == "batchId" and resource_type == "document" and scalar is None:
            continue
        if not isinstance(scalar, str):
            raise OperationContractError()

    if (
        result.get("contractVersion") != identity.contract_version
        or result.get("operation") != identity.operation
    ):
        raise OperationContractError()
    resource_field = "batchId" if resource_type == "batch" else "documentId"
    if result.get(resource_field) != resource_id:
        raise OperationContractError()
    schema_version = result.get("schemaVersion")
    status = result.get("status")
    created_at = result.get("createdAt")
    if (
        not isinstance(schema_version, str)
        or _SCHEMA_VERSION_PATTERN.fullmatch(schema_version) is None
        or not isinstance(status, str)
        or _STATUS_PATTERN.fullmatch(status) is None
        or not isinstance(created_at, str)
    ):
        raise OperationContractError()
    expected_schema_status = {
        "batch": ("scanalyze.batch-create-result.v1", "OPEN"),
        "document": ("scanalyze.document-create-result.v1", "UPLOAD_PENDING"),
    }[resource_type]
    if (schema_version, status) != expected_schema_status:
        raise OperationContractError()
    _parse_timestamp(created_at)
    batch_id = result.get("batchId")
    if batch_id is not None:
        _validated_resource_id(batch_id)
    if resource_type == "document":
        content_type = result.get("contentType")
        if (
            not isinstance(content_type, str)
            or _CONTENT_TYPE_PATTERN.fullmatch(content_type) is None
            or content_type not in _DOCUMENT_CONTENT_TYPES
        ):
            raise OperationContractError()

    try:
        encoded = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise OperationContractError() from error
    if len(encoded) > _MAX_DURABLE_RESPONSE_BYTES:
        raise OperationContractError()
    return result


def _validated_failure_code(value: object) -> str:
    if not isinstance(value, str) or _FAILURE_CODE_PATTERN.fullmatch(value) is None:
        raise OperationContractError()
    return value


def _operation_item(record: OperationRecord) -> dict[str, Any]:
    identity = record.identity
    key = _operation_key(identity)
    item: dict[str, Any] = {
        **key,
        "schema_version": OPERATION_SCHEMA_VERSION,
        "contract_version": identity.contract_version,
        "operation": identity.operation,
        "actor_digest": identity.actor_digest,
        "customer_id": identity.customer_id,
        "deployment_id": identity.deployment_id,
        "key_digest": identity.key_digest,
        "request_digest": _normalized_digest(record.request_digest),
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "durable_response": dict(record.durable_response),
        "state": record.state.value,
        "version": record.version,
        "created_at": _timestamp(record.created_at),
        "updated_at": _timestamp(record.updated_at),
        "expires_at": _timestamp(record.expires_at),
    }
    if record.completed_at is not None:
        item["completed_at"] = _timestamp(record.completed_at)
    if record.failure_code is not None:
        item["failure_code"] = _validated_failure_code(record.failure_code)
    return item


def _record_from_item(item: object) -> OperationRecord:
    if not isinstance(item, Mapping):
        raise OperationContractError()
    required = {
        "pk",
        "sk",
        "schema_version",
        "contract_version",
        "operation",
        "actor_digest",
        "customer_id",
        "deployment_id",
        "key_digest",
        "request_digest",
        "resource_type",
        "resource_id",
        "durable_response",
        "state",
        "version",
        "created_at",
        "updated_at",
        "expires_at",
    }
    optional = {"completed_at", "failure_code"}
    if not required.issubset(item) or not set(item).issubset(required | optional):
        raise OperationContractError()
    if item.get("schema_version") != OPERATION_SCHEMA_VERSION:
        raise OperationContractError()

    identity = OperationIdentity(
        contract_version=_validated_identifier(item.get("contract_version")),
        operation=str(item.get("operation")),
        actor_digest=_normalized_digest(item.get("actor_digest")),
        customer_id=_validated_identifier(item.get("customer_id")),
        deployment_id=_validated_identifier(item.get("deployment_id")),
        key_digest=_normalized_digest(item.get("key_digest")),
    )
    if {"pk": item.get("pk"), "sk": item.get("sk")} != _operation_key(identity):
        raise OperationContractError()
    request_digest = _normalized_digest(item.get("request_digest"))
    resource_type = _validated_identifier(item.get("resource_type"))
    resource_id = _validated_resource_id(item.get("resource_id"))
    response = _validated_durable_response(
        item.get("durable_response"),
        identity=identity,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    state = _state(item.get("state"))
    version = _positive_integer(item.get("version"))
    created_at = _parse_timestamp(item.get("created_at"))
    updated_at = _parse_timestamp(item.get("updated_at"))
    expires_at = _parse_timestamp(item.get("expires_at"))
    completed_at = (
        _parse_timestamp(item.get("completed_at"))
        if item.get("completed_at") is not None
        else None
    )
    failure_code = (
        _validated_failure_code(item.get("failure_code"))
        if item.get("failure_code") is not None
        else None
    )
    if not (created_at <= updated_at and created_at < expires_at):
        raise OperationContractError()
    if completed_at is not None and not (created_at <= completed_at <= updated_at):
        raise OperationContractError()
    if (state in _FAILURE_STATES) != (failure_code is not None):
        raise OperationContractError()
    if (state in _COMPLETED_STATES) != (completed_at is not None):
        raise OperationContractError()
    if state is OperationState.EXPIRED:
        if updated_at < expires_at:
            raise OperationContractError()
    elif updated_at >= expires_at:
        raise OperationContractError()

    return OperationRecord(
        schema_version=OPERATION_SCHEMA_VERSION,
        contract_version=identity.contract_version,
        operation=identity.operation,
        actor_digest=identity.actor_digest,
        customer_id=identity.customer_id,
        deployment_id=identity.deployment_id,
        key_digest=identity.key_digest,
        request_digest=request_digest,
        resource_type=resource_type,
        resource_id=resource_id,
        durable_response=response,
        state=state,
        version=version,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        completed_at=completed_at,
        failure_code=failure_code,
    )


class DynamoOperationsRepository:
    """Create-only and exact-CAS access to the durable operation ledger."""

    def __init__(self, table: Any) -> None:
        if table is None:
            raise OperationContractError()
        self.table = table

    def load(self, identity: OperationIdentity) -> OperationRecord | None:
        response = self.table.get_item(
            Key=_operation_key(identity),
            ConsistentRead=True,
        )
        if not isinstance(response, Mapping):
            raise OperationContractError()
        if "Item" not in response:
            return None
        item = response["Item"]
        if item is None:
            raise OperationContractError()
        record = _record_from_item(item)
        if record.identity != identity:
            raise OperationContractError()
        return record

    def reserve(
        self,
        identity: OperationIdentity,
        *,
        request_digest: str,
        resource_type: str,
        resource_id: str,
        durable_response: Mapping[str, DurableScalar],
        now: datetime,
        expires_at: datetime,
    ) -> ReservationOutcome:
        request_digest = _normalized_digest(request_digest)
        resource_type = _validated_identifier(resource_type)
        resource_id = _validated_resource_id(resource_id)
        if _OPERATION_RESOURCE_TYPES[identity.operation] != resource_type:
            raise OperationContractError()
        now = _aware_utc(now)
        expires_at = _aware_utc(expires_at)
        if expires_at <= now:
            raise OperationContractError()
        response = _validated_durable_response(
            durable_response,
            identity=identity,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        if _parse_timestamp(response["createdAt"]) != now:
            raise OperationContractError()
        candidate = OperationRecord(
            schema_version=OPERATION_SCHEMA_VERSION,
            contract_version=identity.contract_version,
            operation=identity.operation,
            actor_digest=identity.actor_digest,
            customer_id=identity.customer_id,
            deployment_id=identity.deployment_id,
            key_digest=identity.key_digest,
            request_digest=request_digest,
            resource_type=resource_type,
            resource_id=resource_id,
            durable_response=response,
            state=OperationState.PENDING,
            version=1,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
        )
        try:
            self.table.put_item(
                Item=_operation_item(candidate),
                ConditionExpression="attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
            )
            return ReservationOutcome(record=candidate, created_here=True)
        except Exception as error:
            try:
                current = self.load(identity)
            except OperationContractError:
                raise
            except Exception as read_error:
                raise OperationPersistenceAmbiguous() from read_error
            if current is None:
                raise OperationPersistenceAmbiguous() from error
            if (
                current.request_digest != request_digest
                or current.resource_type != resource_type
            ):
                raise OperationConflict() from error
            # If a non-conditional error was raised after DynamoDB applied our
            # exact candidate, this caller remains the reservation winner and
            # must perform the one business write. Treating it as a replay
            # would strand the operation in PENDING with zero effects.
            if (
                _error_code(error) != _CONDITIONAL_FAILURE
                and current == candidate
            ):
                return ReservationOutcome(record=current, created_here=True)
            return ReservationOutcome(record=current, created_here=False)

    def transition(
        self,
        identity: OperationIdentity,
        *,
        expected_state: OperationState,
        expected_version: int,
        next_state: OperationState,
        durable_response: Mapping[str, DurableScalar] | None = None,
        failure_code: str | None = None,
        completed_at: datetime | None = None,
        updated_at: datetime,
    ) -> OperationRecord:
        expected_state = _state(expected_state)
        next_state = _state(next_state)
        expected_version = _positive_integer(expected_version)
        updated_at = _aware_utc(updated_at)
        explicit_completed_at = completed_at is not None
        if completed_at is not None:
            completed_at = _aware_utc(completed_at)
        if next_state in _FAILURE_STATES:
            failure_code = _validated_failure_code(failure_code)
        elif failure_code is not None:
            raise OperationContractError()

        current = self.load(identity)
        if current is None:
            raise OperationConflict()

        response = (
            _validated_durable_response(
                durable_response,
                identity=identity,
                resource_type=current.resource_type,
                resource_id=current.resource_id,
            )
            if durable_response is not None
            else dict(current.durable_response)
        )
        if dict(response) != dict(current.durable_response):
            raise OperationContractError()
        effective_completed_at = completed_at
        if next_state in _COMPLETED_STATES and effective_completed_at is None:
            # Logical expiry does not erase an earlier terminal completion.
            # A still-pending operation completes at the expiry transition.
            effective_completed_at = current.completed_at or updated_at
        if next_state not in _COMPLETED_STATES and effective_completed_at is not None:
            raise OperationContractError()

        if current.state is next_state and current.version == expected_version + 1:
            if self._matches_transition(
                current,
                response=response,
                failure_code=failure_code,
                completed_at=completed_at if explicit_completed_at else None,
            ):
                return current
            raise OperationConflict()
        if current.state is not expected_state or current.version != expected_version:
            raise OperationConflict()
        if next_state not in _ALLOWED_TRANSITIONS[expected_state]:
            raise OperationContractError()
        if updated_at < current.updated_at:
            raise OperationContractError()
        if completed_at is not None and not (
            current.created_at <= completed_at <= updated_at
        ):
            raise OperationContractError()
        if updated_at >= current.expires_at and next_state is not OperationState.EXPIRED:
            raise OperationConflict()
        if next_state is OperationState.EXPIRED and updated_at < current.expires_at:
            raise OperationContractError()

        next_version = expected_version + 1
        expression_names = {
            "#state": "state",
            "#version": "version",
            "#updated_at": "updated_at",
        }
        expression_values: dict[str, Any] = {
            ":expected_state": expected_state.value,
            ":expected_version": expected_version,
            ":next_state": next_state.value,
            ":next_version": next_version,
            ":updated_at": _timestamp(updated_at),
            ":durable_response": response,
            ":schema_version": OPERATION_SCHEMA_VERSION,
            ":contract_version": identity.contract_version,
            ":operation": identity.operation,
            ":actor_digest": identity.actor_digest,
            ":customer_id": identity.customer_id,
            ":deployment_id": identity.deployment_id,
            ":key_digest": identity.key_digest,
            ":request_digest": current.request_digest,
            ":resource_type": current.resource_type,
            ":resource_id": current.resource_id,
        }
        set_parts = [
            "#state = :next_state",
            "#version = :next_version",
            "#updated_at = :updated_at",
            "durable_response = :durable_response",
        ]
        remove_parts: list[str] = []
        if failure_code is None:
            remove_parts.append("failure_code")
        else:
            set_parts.append("failure_code = :failure_code")
            expression_values[":failure_code"] = failure_code
        if effective_completed_at is None:
            remove_parts.append("completed_at")
        else:
            set_parts.append("completed_at = :completed_at")
            expression_values[":completed_at"] = _timestamp(effective_completed_at)

        condition = (
            "#state = :expected_state AND #version = :expected_version "
            "AND schema_version = :schema_version "
            "AND contract_version = :contract_version AND operation = :operation "
            "AND actor_digest = :actor_digest AND customer_id = :customer_id "
            "AND deployment_id = :deployment_id AND key_digest = :key_digest "
            "AND request_digest = :request_digest AND resource_type = :resource_type "
            "AND resource_id = :resource_id"
        )
        update = "SET " + ", ".join(set_parts)
        if remove_parts:
            update += " REMOVE " + ", ".join(remove_parts)

        write_error: Exception | None = None
        try:
            self.table.update_item(
                Key=_operation_key(identity),
                UpdateExpression=update,
                ConditionExpression=condition,
                ExpressionAttributeNames=expression_names,
                ExpressionAttributeValues=expression_values,
            )
        except Exception as error:
            write_error = error

        try:
            verified = self.load(identity)
        except Exception as read_error:
            raise OperationPersistenceAmbiguous() from read_error
        if (
            verified is not None
            and verified.state is next_state
            and verified.version == next_version
        ):
            if self._matches_transition(
                verified,
                response=response,
                failure_code=failure_code,
                completed_at=effective_completed_at,
            ):
                return verified
            raise OperationConflict() from write_error
        if write_error is not None and _error_code(write_error) == _CONDITIONAL_FAILURE:
            raise OperationConflict() from write_error
        if write_error is not None:
            raise OperationPersistenceAmbiguous() from write_error
        raise OperationPersistenceAmbiguous()

    @staticmethod
    def _matches_transition(
        record: OperationRecord,
        *,
        response: Mapping[str, DurableScalar],
        failure_code: str | None,
        completed_at: datetime | None,
    ) -> bool:
        if dict(record.durable_response) != dict(response) or record.failure_code != failure_code:
            return False
        return completed_at is None or record.completed_at == completed_at


# Short name for composition code; both names refer to the same reviewed adapter.
OperationsRepository = DynamoOperationsRepository


__all__ = [
    "DynamoOperationsRepository",
    "OperationConflict",
    "OperationContractError",
    "OperationIdentity",
    "OperationPersistenceAmbiguous",
    "OperationRecord",
    "OperationRepositoryError",
    "OperationState",
    "OperationsRepository",
    "ReservationOutcome",
]
