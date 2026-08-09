"""Closed public contract primitives for the GUG-354 document journey.

This module is deliberately free of AWS clients.  It owns the runtime models,
canonical request hashing, principal/key pseudonymisation, internal-status
projection, and the single supported public result adapter.  The authoritative
wire schemas live in ``schemas/scanalyze-document-journey*.json`` and parity is
enforced by focused tests.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import date as DateValue
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, TypeVar
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from typing_extensions import Annotated

from .document_contracts import canonical_document_content_type
from .repositories.operations import OperationState as LedgerState


API_NAMESPACE = "/api/v2"
CONTRACT_HEADER = "X-Scanalyze-Contract-Version"
IDEMPOTENCY_HEADER = "Idempotency-Key"
CONTRACT_VERSION = "scanalyze.document-journey.v1"
ERROR_SCHEMA_VERSION = "scanalyze.error.v1"
RESULT_SCHEMA_VERSION = "scanalyze.document-result.v1"
STATUS_SCHEMA_VERSION = "scanalyze.document-status.v1"
CANONICAL_REQUEST_DOMAIN = b"scanalyze.document-journey.canonical-request.v1\x00"
IDEMPOTENCY_KEY_DOMAIN = b"scanalyze.document-journey.idempotency-key.v1\x00"
ACTOR_IDENTITY_DOMAIN = b"scanalyze.document-journey.actor.v1\x00"

MAX_DOCUMENT_BYTES = 512 * 1024 * 1024
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_HEX_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_CUSTOMER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")
_DEPLOYMENT_RE = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
_FILENAME_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f/\\]")
_MAX_REQUEST_BYTES = 1_048_576
_MAX_SAFE_INTEGER = 2**53 - 1


def _to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


class ContractModel(BaseModel):
    """Base for immutable, closed public and durable contract records."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class InternalArtifactModel(BaseModel):
    """Allowlisted projection model for nested producer-owned containers.

    The canonical bank producer intentionally permits additive members in its
    nested dictionaries.  Those members are ignored at this trust boundary;
    the top-level artifact and every public model remain closed.
    """

    model_config = ConfigDict(extra="ignore", frozen=True, str_strip_whitespace=True)


class JourneyContractError(ValueError):
    """Safe local contract failure; the caller maps it to a public error code."""


class UnsupportedInternalState(JourneyContractError):
    """An internal value or transition is not in the reviewed adapter table."""


class MalformedInternalResult(JourneyContractError):
    """A worker artifact cannot be safely projected to the public result."""


class OperationKind(str, Enum):
    BATCH_CREATE = "batches.create"
    DOCUMENT_CREATE = "documents.create"


class DocumentContentType(str, Enum):
    PDF = "application/pdf"
    JPEG = "image/jpeg"
    PNG = "image/png"
    TIFF = "image/tiff"


class DocumentLifecycle(str, Enum):
    UPLOAD_PENDING = "UPLOAD_PENDING"
    SUBMITTED = "SUBMITTED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PipelineStage(str, Enum):
    INGEST = "INGEST"
    OCR = "OCR"
    CLASSIFY = "CLASSIFY"
    BANK_EXTRACT = "BANK_EXTRACT"
    PERSONAL_EXTRACT = "PERSONAL_EXTRACT"
    VALIDATE = "VALIDATE"
    TERMINAL = "TERMINAL"


class StageState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ProcessingCondition(str, Enum):
    ACTIVE = "ACTIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FailureDisposition(str, Enum):
    RETRYABLE = "RETRYABLE"
    TERMINAL = "TERMINAL"


class SafeFailureCode(str, Enum):
    DOCUMENT_PROCESSING_FAILED = "DOCUMENT_PROCESSING_FAILED"
    OCR_FAILED = "OCR_FAILED"
    ENQUEUE_FAILED = "ENQUEUE_FAILED"


class RetryClass(str, Enum):
    NOT_RETRYABLE = "NOT_RETRYABLE"
    RETRYABLE_WITH_BACKOFF = "RETRYABLE_WITH_BACKOFF"
    RETRY_ONLY_AFTER_RECONCILIATION = "RETRY_ONLY_AFTER_RECONCILIATION"
    TERMINAL = "TERMINAL"
    UNKNOWN_OR_QUARANTINED = "UNKNOWN_OR_QUARANTINED"


class ErrorCode(str, Enum):
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    AUTHENTICATION_INVALID = "AUTHENTICATION_INVALID"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    NOT_FOUND = "NOT_FOUND"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    RESULT_NOT_READY = "RESULT_NOT_READY"
    SEMANTIC_VALIDATION_FAILED = "SEMANTIC_VALIDATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    REQUEST_TIMEOUT = "REQUEST_TIMEOUT"
    UNSUPPORTED_CONTRACT_VERSION = "UNSUPPORTED_CONTRACT_VERSION"
    UNKNOWN_WRITE_OUTCOME = "UNKNOWN_WRITE_OUTCOME"
    STATE_CONFLICT = "STATE_CONFLICT"
    UNSUPPORTED_STATE = "UNSUPPORTED_STATE"
    MALFORMED_INTERNAL_RESULT = "MALFORMED_INTERNAL_RESULT"
    EXPIRED_OPERATION = "EXPIRED_OPERATION"
    UNSUPPORTED_RESULT_TYPE = "UNSUPPORTED_RESULT_TYPE"


class ReconciliationFailureCode(str, Enum):
    CREATE_FAILED_RETRYABLE = "CREATE_FAILED_RETRYABLE"
    CREATE_FAILED_TERMINAL = "CREATE_FAILED_TERMINAL"
    UNKNOWN_WRITE_OUTCOME = "UNKNOWN_WRITE_OUTCOME"
    OPERATION_EXPIRED = "OPERATION_EXPIRED"


def require_contract_version(value: str | None) -> str:
    if value != CONTRACT_VERSION:
        raise JourneyContractError("unsupported contract version")
    return value


def validate_idempotency_key(value: str) -> str:
    """Accept only canonical lowercase UUIDv4 values from crypto.randomUUID()."""

    if not isinstance(value, str) or not _UUID4_RE.fullmatch(value):
        raise JourneyContractError("invalid idempotency key")
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise JourneyContractError("invalid idempotency key") from None
    if parsed.version != 4 or str(parsed) != value:
        raise JourneyContractError("invalid idempotency key")
    return value


def _digest(domain: bytes, value: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + value).hexdigest()


def idempotency_key_digest(value: str) -> str:
    """Return the only form of an idempotency key allowed in durable storage."""

    return _digest(IDEMPOTENCY_KEY_DOMAIN, validate_idempotency_key(value).encode("ascii"))


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JourneyContractError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite_constant(_value: str) -> None:
    raise JourneyContractError("non-finite JSON number")


def strict_json_object(
    raw: bytes | str,
    *,
    max_bytes: int = _MAX_REQUEST_BYTES,
) -> dict[str, Any]:
    """Parse one JSON object while rejecting duplicate keys and NaN/Infinity."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= 20_971_520:
        raise JourneyContractError("JSON size limit is invalid")
    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise JourneyContractError("request body is too large")
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise JourneyContractError("request body is not valid UTF-8") from None
    elif isinstance(raw, str):
        try:
            if len(raw.encode("utf-8", errors="strict")) > max_bytes:
                raise JourneyContractError("request body is too large")
        except UnicodeEncodeError:
            raise JourneyContractError("request body is not valid UTF-8") from None
    else:
        raise JourneyContractError("malformed JSON object")
    if raw.startswith("\ufeff"):
        raise JourneyContractError("request body must not contain a byte-order mark")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite_constant,
        )
    except JourneyContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        raise JourneyContractError("malformed JSON object") from None
    if not isinstance(parsed, dict):
        raise JourneyContractError("request body must be a JSON object")
    _validate_json_value(parsed)
    return parsed


TContractModel = TypeVar("TContractModel", bound=ContractModel)


def parse_strict_request(raw: bytes | str, model: type[TContractModel]) -> TContractModel:
    """Parse at the byte boundary, then enforce a closed Pydantic request model."""

    payload = strict_json_object(raw)
    # Public requests accept only the documented wire aliases.  ContractModel
    # permits Python field names for safe internal construction, but that must
    # not silently broaden the JSON surface to snake_case aliases.
    allowed_wire_keys = {
        field.alias or field_name for field_name, field in model.model_fields.items()
    }
    if any(key not in allowed_wire_keys for key in payload):
        raise JourneyContractError("request contains an unknown field")
    return model.model_validate(payload)


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise JourneyContractError("unpaired surrogate is not valid JSON")
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise JourneyContractError("JSON integer exceeds the canonical safe range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise JourneyContractError("non-finite JSON number")
        return
    if isinstance(value, list) or isinstance(value, tuple):
        for member in value:
            _validate_json_value(member)
        return
    if isinstance(value, Mapping):
        for key, member in value.items():
            if not isinstance(key, str):
                raise JourneyContractError("JSON object keys must be strings")
            _validate_json_value(member)
        return
    raise JourneyContractError("unsupported canonical JSON type")


def _canonical_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_request_digest(operation: OperationKind | str, request: ContractModel) -> str:
    """Hash only a validated closed semantic request with explicit domain/version."""

    try:
        operation_value = OperationKind(operation).value
    except (TypeError, ValueError):
        raise JourneyContractError("unsupported operation") from None
    if not isinstance(request, ContractModel):
        raise JourneyContractError("canonical request must be a closed contract model")
    expected_model = (
        BatchCreateRequest
        if operation_value == OperationKind.BATCH_CREATE.value
        else DocumentCreateRequest
    )
    if type(request) is not expected_model:
        raise JourneyContractError("request model does not match operation")
    semantic_request = request.model_dump(mode="json", by_alias=True, exclude_none=True)
    frame = {
        "contractVersion": CONTRACT_VERSION,
        "operation": operation_value,
        "request": semantic_request,
    }
    return _digest(CANONICAL_REQUEST_DOMAIN, _canonical_bytes(frame))


class BatchCreateRequest(ContractModel):
    pass


class DocumentCreateRequest(ContractModel):
    filename: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    content_type: DocumentContentType
    content_length: int | None = Field(default=None, ge=0, le=MAX_DOCUMENT_BYTES)
    batch_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None

    @field_validator("filename")
    @classmethod
    def _safe_filename(cls, value: str | None) -> str | None:
        if value is not None and (
            _FILENAME_CONTROL_RE.search(value) or value.strip() in {".", ".."}
        ):
            raise ValueError("filename contains forbidden path syntax")
        return value

    @field_validator("content_length", mode="before")
    @classmethod
    def _integer_content_length(cls, value: Any) -> Any:
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError("contentLength must be an integer")
        return value

    @field_validator("content_type", mode="before")
    @classmethod
    def _canonical_content_type(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        canonical = canonical_document_content_type(value)
        return canonical if canonical is not None else value


class SubmitDocumentRequest(ContractModel):
    stage: Literal["ingest"] = "ingest"


class OwnerScope(ContractModel):
    """Durable owner scope; actor is pseudonymised and never returned publicly."""

    actor_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    customer_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")
    ]
    deployment_id: Annotated[
        str, StringConstraints(pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
    ]


def owner_scope_from_auth(auth: Any) -> OwnerScope:
    """Derive owner authority fail-closed from a verified AuthContext-like object."""

    principal_type = getattr(auth, "principal_type", None)
    if principal_type in {"user", "local_mock"}:
        actor = getattr(auth, "subject", None)
    elif principal_type == "m2m":
        actor = getattr(auth, "client_id", None)
    else:
        raise JourneyContractError("unsupported authenticated principal")
    customer_id = getattr(auth, "customer_id", None)
    deployment_id = getattr(auth, "deployment_id", None)
    if not isinstance(actor, str) or not actor.strip():
        raise JourneyContractError("authenticated actor identity is missing")
    if not isinstance(customer_id, str) or not _CUSTOMER_RE.fullmatch(customer_id):
        raise JourneyContractError("authenticated customer identity is invalid")
    if not isinstance(deployment_id, str) or not _DEPLOYMENT_RE.fullmatch(deployment_id):
        raise JourneyContractError("authenticated deployment identity is invalid")
    actor_frame = _canonical_bytes(
        {"principalType": principal_type, "reference": actor.strip()}
    )
    return OwnerScope(
        actor_digest=_digest(ACTOR_IDENTITY_DOMAIN, actor_frame),
        customer_id=customer_id,
        deployment_id=deployment_id,
    )


class BatchDurableResponse(ContractModel):
    schema_version: Literal["scanalyze.batch-create-result.v1"] = (
        "scanalyze.batch-create-result.v1"
    )
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    operation: Literal[OperationKind.BATCH_CREATE] = OperationKind.BATCH_CREATE
    batch_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    status: Literal["OPEN"] = "OPEN"
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware_created_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class DocumentDurableResponse(ContractModel):
    schema_version: Literal["scanalyze.document-create-result.v1"] = (
        "scanalyze.document-create-result.v1"
    )
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    operation: Literal[OperationKind.DOCUMENT_CREATE] = OperationKind.DOCUMENT_CREATE
    document_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    batch_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    status: Literal["UPLOAD_PENDING"] = "UPLOAD_PENDING"
    content_type: DocumentContentType
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware_created_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class UploadRequiredHeaders(ContractModel):
    content_type: DocumentContentType = Field(alias="Content-Type")


class UploadCapability(ContractModel):
    method: Literal["PUT"] = "PUT"
    url: Annotated[str, StringConstraints(min_length=9, max_length=8192)]
    expires_at: datetime
    required_headers: UploadRequiredHeaders

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("upload capability must use HTTPS")
        return value

    @field_validator("expires_at")
    @classmethod
    def _aware_expires_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class BatchCreateResponse(ContractModel):
    schema_version: Literal["scanalyze.operation-response.v1"] = (
        "scanalyze.operation-response.v1"
    )
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    replayed: bool
    durable_response: BatchDurableResponse


class DocumentCreateResponse(ContractModel):
    schema_version: Literal["scanalyze.operation-response.v1"] = (
        "scanalyze.operation-response.v1"
    )
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    replayed: bool
    durable_response: DocumentDurableResponse
    upload_capability: UploadCapability | None = None

    @model_validator(mode="after")
    def _capability_matches_replay_state(self) -> "DocumentCreateResponse":
        if not self.replayed and self.upload_capability is None:
            raise ValueError("first document response requires an upload capability")
        return self


class SubmitDocumentResponse(ContractModel):
    schema_version: Literal["scanalyze.document-submit.v1"] = "scanalyze.document-submit.v1"
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    document_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    stage: Literal["ingest"] = "ingest"
    enqueued: bool


class UploadCapabilityResponse(ContractModel):
    schema_version: Literal["scanalyze.upload-capability.v1"] = (
        "scanalyze.upload-capability.v1"
    )
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    document_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    upload_capability: UploadCapability


DurableResponse = Annotated[
    BatchDurableResponse | DocumentDurableResponse,
    Field(discriminator="operation"),
]


class ReconciliationResponse(ContractModel):
    schema_version: Literal["scanalyze.reconciliation.v1"] = "scanalyze.reconciliation.v1"
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    operation: OperationKind
    ledger_state: LedgerState
    durable_response: DurableResponse | None = None
    failure_code: ReconciliationFailureCode | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    expires_at: datetime

    @field_validator("created_at", "updated_at", "completed_at", "expires_at")
    @classmethod
    def _aware_times(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware(value)

    @model_validator(mode="after")
    def _consistent_state(self) -> "ReconciliationResponse":
        if self.updated_at < self.created_at or self.expires_at <= self.created_at:
            raise ValueError("reconciliation timestamps are inconsistent")
        if self.ledger_state is LedgerState.EXPIRED:
            if self.updated_at < self.expires_at:
                raise ValueError("EXPIRED reconciliation must be observed after expiry")
        elif self.updated_at >= self.expires_at:
            raise ValueError("non-expired reconciliation must precede expiry")
        if self.ledger_state is LedgerState.SUCCEEDED:
            if self.durable_response is None or self.completed_at is None:
                raise ValueError("SUCCEEDED reconciliation requires durable response")
            if self.failure_code is not None:
                raise ValueError("SUCCEEDED reconciliation cannot carry a failure")
        elif self.durable_response is not None:
            raise ValueError("only SUCCEEDED reconciliation can carry durable response")
        if self.durable_response is not None and self.durable_response.operation != self.operation:
            raise ValueError("operation does not match durable response")
        expected_failure = {
            LedgerState.FAILED_RETRYABLE: ReconciliationFailureCode.CREATE_FAILED_RETRYABLE,
            LedgerState.FAILED_TERMINAL: ReconciliationFailureCode.CREATE_FAILED_TERMINAL,
            LedgerState.UNKNOWN_OR_QUARANTINED: ReconciliationFailureCode.UNKNOWN_WRITE_OUTCOME,
            LedgerState.EXPIRED: ReconciliationFailureCode.OPERATION_EXPIRED,
        }.get(self.ledger_state)
        if expected_failure is not None and self.failure_code is not expected_failure:
            raise ValueError("ledger state requires its stable failure code")
        terminal_failure = self.ledger_state in {
            LedgerState.FAILED_TERMINAL,
            LedgerState.UNKNOWN_OR_QUARANTINED,
            LedgerState.EXPIRED,
        }
        if terminal_failure and self.completed_at is None:
            raise ValueError("terminal reconciliation requires completedAt")
        if self.ledger_state is LedgerState.FAILED_RETRYABLE and self.completed_at is not None:
            raise ValueError("FAILED_RETRYABLE reconciliation is resumable")
        if self.ledger_state is LedgerState.PENDING and (
            self.failure_code is not None or self.completed_at is not None
        ):
            raise ValueError("PENDING reconciliation cannot be completed")
        if self.completed_at is not None and not (
            self.created_at <= self.completed_at <= self.updated_at
        ):
            raise ValueError("completion timestamp is inconsistent")
        return self


class DocumentProgress(ContractModel):
    attempt: StrictInt | None = Field(default=None, ge=0, le=1000)
    completed_stages: StrictInt | None = Field(default=None, ge=0, le=10)
    total_stages: StrictInt | None = Field(default=None, ge=1, le=10)

    @model_validator(mode="after")
    def _bounded_progress(self) -> "DocumentProgress":
        if (
            self.completed_stages is not None
            and self.total_stages is not None
            and self.completed_stages > self.total_stages
        ):
            raise ValueError("completedStages exceeds totalStages")
        return self


class DocumentStatusResponse(ContractModel):
    schema_version: Literal[STATUS_SCHEMA_VERSION] = STATUS_SCHEMA_VERSION
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    batch_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    document_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    lifecycle: DocumentLifecycle
    current_stage: PipelineStage
    stage_state: StageState
    processing_condition: ProcessingCondition
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None = None
    correlation_reference: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    ] | None = None
    progress: DocumentProgress | None = None
    failure_disposition: FailureDisposition | None = None
    safe_failure_code: SafeFailureCode | None = None

    @field_validator("created_at", "updated_at", "terminal_at")
    @classmethod
    def _aware_times(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware(value)

    @model_validator(mode="after")
    def _consistent_status(self) -> "DocumentStatusResponse":
        if self.updated_at < self.created_at:
            raise ValueError("updatedAt precedes createdAt")
        terminal = self.lifecycle in {
            DocumentLifecycle.COMPLETED,
            DocumentLifecycle.FAILED,
        }
        if terminal != (self.terminal_at is not None):
            raise ValueError("terminal lifecycle and terminalAt disagree")
        if terminal and self.terminal_at is not None and not (
            self.created_at <= self.terminal_at <= self.updated_at
        ):
            raise ValueError("terminalAt is inconsistent")
        if terminal:
            if self.current_stage is not PipelineStage.TERMINAL:
                raise ValueError("terminal lifecycle requires TERMINAL stage")
            if self.processing_condition is not ProcessingCondition.NOT_APPLICABLE:
                raise ValueError("terminal lifecycle cannot be actively processing")
        elif self.current_stage is PipelineStage.TERMINAL:
            raise ValueError("nonterminal lifecycle cannot use TERMINAL stage")
        retryable_enqueue_failure = (
            self.lifecycle is DocumentLifecycle.SUBMITTED
            and self.current_stage is PipelineStage.INGEST
            and self.stage_state is StageState.FAILED
            and self.processing_condition is ProcessingCondition.NOT_APPLICABLE
            and self.failure_disposition is FailureDisposition.RETRYABLE
            and self.safe_failure_code is SafeFailureCode.ENQUEUE_FAILED
        )
        if self.lifecycle is DocumentLifecycle.UPLOAD_PENDING and (
            self.current_stage is not PipelineStage.INGEST
            or self.stage_state is not StageState.PENDING
            or self.processing_condition is not ProcessingCondition.ACTIVE
        ):
            raise ValueError("pre-processing lifecycle has an invalid stage projection")
        if self.lifecycle is DocumentLifecycle.SUBMITTED and not retryable_enqueue_failure:
            if (
                self.current_stage is not PipelineStage.INGEST
                or self.stage_state not in {StageState.PENDING, StageState.RUNNING}
                or self.processing_condition is not ProcessingCondition.ACTIVE
            ):
                raise ValueError("SUBMITTED has an invalid stage projection")
        if self.lifecycle is DocumentLifecycle.PROCESSING:
            reviewed_processing_states = {
                (PipelineStage.OCR, StageState.RUNNING),
                (PipelineStage.OCR, StageState.SUCCEEDED),
                (PipelineStage.CLASSIFY, StageState.PENDING),
                (PipelineStage.CLASSIFY, StageState.SUCCEEDED),
                (PipelineStage.BANK_EXTRACT, StageState.RUNNING),
                (PipelineStage.BANK_EXTRACT, StageState.SUCCEEDED),
                (PipelineStage.PERSONAL_EXTRACT, StageState.RUNNING),
                (PipelineStage.PERSONAL_EXTRACT, StageState.SUCCEEDED),
                (PipelineStage.VALIDATE, StageState.SUCCEEDED),
            }
            if (
                (self.current_stage, self.stage_state)
                not in reviewed_processing_states
                or self.processing_condition is not ProcessingCondition.ACTIVE
            ):
                raise ValueError("PROCESSING has an invalid stage projection")
        if self.lifecycle is DocumentLifecycle.COMPLETED:
            if self.stage_state is not StageState.SUCCEEDED:
                raise ValueError("COMPLETED requires SUCCEEDED terminal stage")
            if self.failure_disposition is not None or self.safe_failure_code is not None:
                raise ValueError("COMPLETED cannot carry failure metadata")
        elif self.lifecycle is DocumentLifecycle.FAILED:
            if self.stage_state is not StageState.FAILED:
                raise ValueError("failed terminal lifecycle requires FAILED stage")
            if self.failure_disposition is None or self.safe_failure_code is None:
                raise ValueError("failed terminal lifecycle requires safe failure metadata")
            if (
                self.failure_disposition is not FailureDisposition.TERMINAL
                or self.safe_failure_code
                not in {
                    SafeFailureCode.DOCUMENT_PROCESSING_FAILED,
                    SafeFailureCode.OCR_FAILED,
                }
            ):
                raise ValueError("FAILED requires reviewed terminal failure metadata")
        elif retryable_enqueue_failure:
            pass
        elif (
            self.failure_disposition is not None
            or self.safe_failure_code is not None
            or self.stage_state is StageState.FAILED
            or self.processing_condition is ProcessingCondition.NOT_APPLICABLE
        ):
            raise ValueError("nonfailed lifecycle carries inconsistent failure metadata")
        return self


_STATUS_ADAPTER: dict[str, tuple[DocumentLifecycle, PipelineStage, StageState]] = {
    "CREATED": (DocumentLifecycle.UPLOAD_PENDING, PipelineStage.INGEST, StageState.PENDING),
    "SUBMITTED": (DocumentLifecycle.SUBMITTED, PipelineStage.INGEST, StageState.RUNNING),
    "OCR": (DocumentLifecycle.PROCESSING, PipelineStage.OCR, StageState.RUNNING),
    "OCR_COMPLETED": (DocumentLifecycle.PROCESSING, PipelineStage.OCR, StageState.SUCCEEDED),
    "CLASSIFY_PENDING": (DocumentLifecycle.PROCESSING, PipelineStage.CLASSIFY, StageState.PENDING),
    "CLASSIFY_COMPLETED": (
        DocumentLifecycle.PROCESSING,
        PipelineStage.CLASSIFY,
        StageState.SUCCEEDED,
    ),
    "BANK_EXTRACTING": (
        DocumentLifecycle.PROCESSING,
        PipelineStage.BANK_EXTRACT,
        StageState.RUNNING,
    ),
    "BANK_EXTRACTED": (
        DocumentLifecycle.PROCESSING,
        PipelineStage.BANK_EXTRACT,
        StageState.SUCCEEDED,
    ),
    "PERSONAL_EXTRACTING": (
        DocumentLifecycle.PROCESSING,
        PipelineStage.PERSONAL_EXTRACT,
        StageState.RUNNING,
    ),
    "PERSONAL_EXTRACTED": (
        DocumentLifecycle.PROCESSING,
        PipelineStage.PERSONAL_EXTRACT,
        StageState.SUCCEEDED,
    ),
    "COMPLETED": (DocumentLifecycle.COMPLETED, PipelineStage.TERMINAL, StageState.SUCCEEDED),
    "FAILED": (DocumentLifecycle.FAILED, PipelineStage.TERMINAL, StageState.FAILED),
    "OCR_FAILED": (DocumentLifecycle.FAILED, PipelineStage.TERMINAL, StageState.FAILED),
}


_STAGE_STATE_ADAPTERS: dict[str, dict[str, StageState]] = {
    "ingest": {
        "ENQUEUE_PENDING": StageState.PENDING,
        "ENQUEUED": StageState.RUNNING,
        "ENQUEUE_FAILED": StageState.FAILED,
    },
    "ocr": {
        "IN_PROGRESS": StageState.RUNNING,
        "COMPLETED": StageState.SUCCEEDED,
    },
    "classify": {
        "ENQUEUED": StageState.RUNNING,
        "PENDING_HANDOFF": StageState.PENDING,
        "COMPLETED": StageState.SUCCEEDED,
    },
    "bank_extract": {
        "ENQUEUED": StageState.RUNNING,
        "WRITING": StageState.RUNNING,
        "COMPLETED": StageState.SUCCEEDED,
    },
    "personal_extract": {
        "ENQUEUED": StageState.RUNNING,
        "WRITING": StageState.RUNNING,
        "COMPLETED": StageState.SUCCEEDED,
    },
    "validate": {"DONE": StageState.SUCCEEDED},
    "persist": {"DONE": StageState.SUCCEEDED},
    "notify": {"DONE": StageState.SUCCEEDED},
}

_TERMINAL_STAGE_RAW_STATE_ALLOWLIST: dict[str, frozenset[str]] = {
    # The ingest producer leaves its durable handoff checkpoint ENQUEUED after a
    # downstream worker has consumed it; this is historical evidence, not an
    # actively running terminal stage.
    "ingest": frozenset({"ENQUEUED"}),
    "ocr": frozenset({"COMPLETED"}),
    "classify": frozenset({"COMPLETED"}),
    "bank_extract": frozenset({"COMPLETED"}),
    "personal_extract": frozenset({"COMPLETED"}),
    "validate": frozenset({"DONE"}),
    "persist": frozenset({"DONE"}),
    "notify": frozenset({"DONE"}),
}


def _processing_condition(updated_at: datetime, now: datetime) -> ProcessingCondition:
    if now < updated_at:
        raise UnsupportedInternalState("updatedAt is in the future")
    return ProcessingCondition.ACTIVE


def _correlation_reference(record: Mapping[str, Any]) -> str | None:
    value = record.get("correlationReference") or record.get("correlationId")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise UnsupportedInternalState("correlation reference is invalid")
    if re.fullmatch(r"^ref_[0-9a-f]{32}$", value):
        return value
    return "ref_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def adapt_internal_document_status(
    record: Mapping[str, Any], *, now: datetime | None = None
) -> DocumentStatusResponse:
    """Project current writer values; any unreviewed value fails closed."""

    try:
        internal_status = record.get("status")
        if not isinstance(internal_status, str) or internal_status not in _STATUS_ADAPTER:
            raise UnsupportedInternalState("unsupported internal document status")
        lifecycle, stage, stage_state = _STATUS_ADAPTER[internal_status]
        created_at = _parse_aware(record.get("createdAt"), "createdAt")
        updated_at = _parse_aware(record.get("updatedAt"), "updatedAt")
        reference_now = _require_aware(now or datetime.now(timezone.utc))

        raw_stages = record.get("stages", {})
        if not isinstance(raw_stages, Mapping):
            raise UnsupportedInternalState("internal stages are malformed")
        stage_evidence: dict[str, tuple[Mapping[str, Any], StageState]] = {}
        for internal_stage, raw_stage in raw_stages.items():
            if internal_stage not in _STAGE_STATE_ADAPTERS:
                raise UnsupportedInternalState("unsupported internal pipeline stage")
            if not isinstance(raw_stage, Mapping) or not raw_stage:
                raise UnsupportedInternalState("internal stage evidence is malformed")
            if "state" in raw_stage:
                raise UnsupportedInternalState("unsupported internal stage state field")
            raw_state = raw_stage.get("status")
            stage_adapter = _STAGE_STATE_ADAPTERS[internal_stage]
            if not isinstance(raw_state, str) or raw_state not in stage_adapter:
                raise UnsupportedInternalState(
                    "internal stage state is invalid for pipeline stage"
                )
            stage_evidence[internal_stage] = (
                raw_stage,
                stage_adapter[raw_state],
            )

        reviewed_domains = {"bank", "personal", "gov"}
        stored_domain = record.get("processing_domain")
        document_route = record.get("documentRoute")
        if stored_domain is not None and stored_domain not in reviewed_domains:
            raise UnsupportedInternalState("unsupported processing domain")
        if document_route is not None and document_route not in (
            reviewed_domains | {"platform", "default"}
        ):
            raise UnsupportedInternalState("unsupported document route")
        if (
            stored_domain in reviewed_domains
            and document_route in reviewed_domains
            and stored_domain != document_route
        ):
            raise UnsupportedInternalState("processing domain and route disagree")
        authoritative_domain = (
            stored_domain
            if stored_domain in reviewed_domains
            else document_route if document_route in reviewed_domains else None
        )
        status_domain = next(
            (
                domain
                for domain in reviewed_domains
                if internal_status.startswith(f"{domain.upper()}_EXTRACT")
            ),
            None,
        )
        if (
            authoritative_domain is not None
            and status_domain is not None
            and authoritative_domain != status_domain
        ):
            raise UnsupportedInternalState("processing domain and document status disagree")
        evidence_domains = {
            name.removesuffix("_extract")
            for name in stage_evidence
            if name in {"bank_extract", "personal_extract"}
        }
        if len(evidence_domains) > 1 or (
            authoritative_domain is not None
            and evidence_domains
            and evidence_domains != {authoritative_domain}
        ):
            raise UnsupportedInternalState("processing domain and stage evidence disagree")

        failed_stages = {
            name
            for name, (_raw_stage, state) in stage_evidence.items()
            if state is StageState.FAILED
        }
        retryable_enqueue_failure = (
            internal_status == "SUBMITTED"
            and failed_stages == {"ingest"}
            and stage_evidence["ingest"][0].get("status") == "ENQUEUE_FAILED"
        )
        if failed_stages and not retryable_enqueue_failure:
            raise UnsupportedInternalState("failed stage contradicts document status")

        if lifecycle is DocumentLifecycle.UPLOAD_PENDING:
            if stage_evidence:
                raise UnsupportedInternalState("pre-submit document has pipeline evidence")
        elif internal_status == "SUBMITTED":
            if set(stage_evidence) != {"ingest"}:
                raise UnsupportedInternalState("SUBMITTED has non-ingest stage evidence")
        elif lifecycle is DocumentLifecycle.PROCESSING:
            common_stages = {"ingest", "ocr", "classify"}
            branch_stages = {"bank_extract", "personal_extract"}
            allowed_by_status = {
                "OCR": {"ingest", "ocr"},
                "OCR_COMPLETED": common_stages | branch_stages,
                "CLASSIFY_PENDING": common_stages,
                "CLASSIFY_COMPLETED": common_stages | branch_stages,
                "BANK_EXTRACTING": common_stages | {"bank_extract"},
                "BANK_EXTRACTED": common_stages | {"bank_extract", "validate"},
                "PERSONAL_EXTRACTING": common_stages | {"personal_extract"},
                "PERSONAL_EXTRACTED": common_stages | {"personal_extract", "validate"},
            }[internal_status]
            if set(stage_evidence) - allowed_by_status:
                raise UnsupportedInternalState("pipeline evidence is ahead of document status")
            observed_branches = set(stage_evidence) & branch_stages
            if len(observed_branches) > 1:
                raise UnsupportedInternalState("multiple extraction branches are present")

            handoff_stages: set[str] = set()
            if internal_status == "OCR_COMPLETED":
                handoff_stages = set(stage_evidence) & ({"classify"} | branch_stages)
            elif internal_status == "CLASSIFY_COMPLETED":
                handoff_stages = set(stage_evidence) & branch_stages
            if len(handoff_stages) > 1 or any(
                (
                    stage_evidence[name][0].get("status")
                )
                != "ENQUEUED"
                for name in handoff_stages
            ):
                raise UnsupportedInternalState("downstream handoff evidence is inconsistent")

            current_stage_key = {
                PipelineStage.INGEST: "ingest",
                PipelineStage.OCR: "ocr",
                PipelineStage.CLASSIFY: "classify",
                PipelineStage.BANK_EXTRACT: "bank_extract",
                PipelineStage.PERSONAL_EXTRACT: "personal_extract",
                PipelineStage.VALIDATE: "validate",
            }.get(stage)
            expected_current_raw_state = {
                "OCR": "IN_PROGRESS",
                "OCR_COMPLETED": "COMPLETED",
                "CLASSIFY_PENDING": "PENDING_HANDOFF",
                "CLASSIFY_COMPLETED": "COMPLETED",
                "BANK_EXTRACTING": "WRITING",
                "BANK_EXTRACTED": "COMPLETED",
                "PERSONAL_EXTRACTING": "WRITING",
                "PERSONAL_EXTRACTED": "COMPLETED",
            }[internal_status]
            if current_stage_key is None or current_stage_key not in stage_evidence:
                raise UnsupportedInternalState("document status lacks current stage evidence")
            if (
                current_stage_key in handoff_stages
                or stage_evidence[current_stage_key][0].get("status")
                != expected_current_raw_state
            ):
                raise UnsupportedInternalState("current stage contradicts document status")

        terminal_at: datetime | None = None
        failure_disposition: FailureDisposition | None = None
        safe_failure_code: SafeFailureCode | None = None
        condition = _processing_condition(updated_at, reference_now)

        if internal_status == "SUBMITTED":
            ingest = stage_evidence.get("ingest")
            if ingest is None:
                raise UnsupportedInternalState("SUBMITTED lacks ingest stage evidence")
            raw_ingest, ingest_state = ingest
            ingest_status = raw_ingest.get("status") or raw_ingest.get("state")
            if ingest_status not in {"ENQUEUE_PENDING", "ENQUEUED", "ENQUEUE_FAILED"}:
                raise UnsupportedInternalState("SUBMITTED ingest stage is inconsistent")
            stage_state = ingest_state
            if ingest_status == "ENQUEUE_FAILED":
                condition = ProcessingCondition.NOT_APPLICABLE
                failure_disposition = FailureDisposition.RETRYABLE
                safe_failure_code = SafeFailureCode.ENQUEUE_FAILED

        if lifecycle is DocumentLifecycle.PROCESSING:
            # Postprocess updates validation under an extracted top-level state.
            # Persist completion and notification are atomic with a terminal
            # top-level state, so observing either here is contradictory.
            if "notify" in stage_evidence:
                raise UnsupportedInternalState("notify evidence precedes terminal state")
            if "persist" in stage_evidence:
                raise UnsupportedInternalState("persist evidence precedes terminal state")
            if "validate" in stage_evidence:
                if internal_status not in {
                    "BANK_EXTRACTED",
                    "PERSONAL_EXTRACTED",
                }:
                    raise UnsupportedInternalState("validate evidence precedes extraction")
                _raw_validate, validate_state = stage_evidence["validate"]
                stage = PipelineStage.VALIDATE
                stage_state = validate_state

            expected_extract_stage = {
                "BANK_EXTRACTING": "bank_extract",
                "BANK_EXTRACTED": "bank_extract",
                "PERSONAL_EXTRACTING": "personal_extract",
                "PERSONAL_EXTRACTED": "personal_extract",
            }.get(internal_status)
            extract_stages = set(stage_evidence) & {
                "bank_extract",
                "personal_extract",
            }
            if (
                expected_extract_stage is not None
                and extract_stages
                and extract_stages != {expected_extract_stage}
            ):
                raise UnsupportedInternalState("domain extraction stage is inconsistent")
            matching_extract_key = expected_extract_stage if expected_extract_stage in stage_evidence else None
            if matching_extract_key is not None:
                _raw_extract, extract_state = stage_evidence[matching_extract_key]
                expected_states = (
                    {StageState.PENDING, StageState.RUNNING}
                    if internal_status.endswith("EXTRACTING")
                    else {StageState.SUCCEEDED}
                )
                if extract_state not in expected_states:
                    raise UnsupportedInternalState("domain extraction state is inconsistent")

        if lifecycle in {DocumentLifecycle.COMPLETED, DocumentLifecycle.FAILED}:
            if internal_status == "OCR_FAILED":
                # The OCR producer changes only the top-level status when
                # Textract fails.  Its IN_PROGRESS checkpoint and the durable
                # ingest ENQUEUED handoff are therefore reviewed historical
                # evidence, not claims that terminal processing is still live.
                reviewed_ocr_failure_states = {
                    "ingest": frozenset({"ENQUEUED"}),
                    "ocr": frozenset({"IN_PROGRESS"}),
                }
                if set(stage_evidence) - set(reviewed_ocr_failure_states):
                    raise UnsupportedInternalState(
                        "OCR failure has downstream stage evidence"
                    )
                if "ocr" not in stage_evidence:
                    raise UnsupportedInternalState(
                        "OCR failure lacks retained OCR stage evidence"
                    )
                for stage_name, (raw_stage, _state) in stage_evidence.items():
                    raw_state = raw_stage.get("status")
                    if raw_state is None:
                        raw_state = raw_stage.get("state")
                    if raw_state not in reviewed_ocr_failure_states[stage_name]:
                        raise UnsupportedInternalState(
                            "OCR failure stage evidence is inconsistent"
                        )
                terminal_at = updated_at
                safe_failure_code = SafeFailureCode.OCR_FAILED
            else:
                for stage_name, (raw_stage, _state) in stage_evidence.items():
                    raw_state = raw_stage.get("status")
                    if raw_state is None:
                        raw_state = raw_stage.get("state")
                    if raw_state not in _TERMINAL_STAGE_RAW_STATE_ALLOWLIST[stage_name]:
                        raise UnsupportedInternalState(
                            "terminal state has nonterminal stage evidence"
                        )
                terminal_at = _parse_aware(record.get("completedAt"), "completedAt")
                persist = stage_evidence.get("persist")
                if persist is None:
                    raise UnsupportedInternalState("terminal state lacks persist evidence")
                raw_persist, persist_state = persist
                if (
                    persist_state is not StageState.SUCCEEDED
                    or raw_persist.get("finalStatus") != internal_status
                    or _parse_aware(raw_persist.get("completedAt"), "persist.completedAt")
                    != terminal_at
                ):
                    raise UnsupportedInternalState("persist and terminal state disagree")
                validation = record.get("validation")
                expected_validation = "PASS" if internal_status == "COMPLETED" else "FAIL"
                if not isinstance(validation, Mapping) or validation.get("status") != expected_validation:
                    raise UnsupportedInternalState("validation and terminal state disagree")
                notify = stage_evidence.get("notify")
                if notify is not None and notify[1] is not StageState.SUCCEEDED:
                    raise UnsupportedInternalState("notify and terminal state disagree")
                if lifecycle is DocumentLifecycle.FAILED:
                    safe_failure_code = SafeFailureCode.DOCUMENT_PROCESSING_FAILED
            condition = ProcessingCondition.NOT_APPLICABLE
            if lifecycle is DocumentLifecycle.FAILED:
                failure_disposition = FailureDisposition.TERMINAL

        progress = None
        attempt = record.get("attempt")
        if attempt is not None:
            if not isinstance(attempt, int) or isinstance(attempt, bool):
                raise UnsupportedInternalState("invalid attempt counter")
            progress = DocumentProgress(attempt=attempt)

        batch_id = record.get("batchId")
        if batch_id is not None:
            batch_id = _normalize_hex_id(batch_id, "batchId")
        return DocumentStatusResponse(
            batch_id=batch_id,
            document_id=_normalize_hex_id(record.get("documentId"), "documentId"),
            lifecycle=lifecycle,
            current_stage=stage,
            stage_state=stage_state,
            processing_condition=condition,
            created_at=created_at,
            updated_at=updated_at,
            terminal_at=terminal_at,
            correlation_reference=_correlation_reference(record),
            progress=progress,
            failure_disposition=failure_disposition,
            safe_failure_code=safe_failure_code,
        )
    except UnsupportedInternalState:
        raise
    except (JourneyContractError, ValidationError, TypeError, ValueError) as error:
        raise UnsupportedInternalState("internal document status is inconsistent") from error


_VALID_TRANSITIONS: dict[DocumentLifecycle, frozenset[DocumentLifecycle]] = {
    DocumentLifecycle.UPLOAD_PENDING: frozenset(
        {
            DocumentLifecycle.UPLOAD_PENDING,
            DocumentLifecycle.SUBMITTED,
        }
    ),
    DocumentLifecycle.SUBMITTED: frozenset(
        {
            DocumentLifecycle.SUBMITTED,
            DocumentLifecycle.PROCESSING,
        }
    ),
    DocumentLifecycle.PROCESSING: frozenset(
        {
            DocumentLifecycle.PROCESSING,
            DocumentLifecycle.COMPLETED,
            DocumentLifecycle.FAILED,
        }
    ),
    DocumentLifecycle.COMPLETED: frozenset({DocumentLifecycle.COMPLETED}),
    DocumentLifecycle.FAILED: frozenset({DocumentLifecycle.FAILED}),
}


def validate_lifecycle_transition(
    previous: DocumentLifecycle, current: DocumentLifecycle
) -> None:
    if current not in _VALID_TRANSITIONS[previous]:
        raise UnsupportedInternalState("invalid public lifecycle transition")


class ErrorField(str, Enum):
    BODY = "body"
    CONTENT_LENGTH = "contentLength"
    CONTENT_TYPE = "contentType"
    DOCUMENT_ID = "documentId"
    IDEMPOTENCY_KEY = "Idempotency-Key"
    OPERATION = "operation"
    STAGE = "stage"
    CONTRACT_VERSION = "X-Scanalyze-Contract-Version"


class ErrorDetails(ContractModel):
    field: ErrorField | None = None
    operation: OperationKind | None = None
    retry_after_seconds: StrictInt | None = Field(default=None, ge=1, le=3600)


class ErrorEnvelope(ContractModel):
    schema_version: Literal[ERROR_SCHEMA_VERSION] = ERROR_SCHEMA_VERSION
    code: ErrorCode
    message: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    correlation_id: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    ]
    retry_class: RetryClass
    details: ErrorDetails | None = None


_ERROR_POLICY: dict[ErrorCode, tuple[int, str, RetryClass]] = {
    ErrorCode.MALFORMED_REQUEST: (400, "The request is malformed.", RetryClass.NOT_RETRYABLE),
    ErrorCode.AUTHENTICATION_REQUIRED: (401, "Authentication is required.", RetryClass.NOT_RETRYABLE),
    ErrorCode.AUTHENTICATION_INVALID: (401, "Authentication is invalid.", RetryClass.NOT_RETRYABLE),
    ErrorCode.AUTHORIZATION_DENIED: (403, "The operation is not authorized.", RetryClass.TERMINAL),
    ErrorCode.NOT_FOUND: (404, "The requested resource was not found.", RetryClass.TERMINAL),
    ErrorCode.IDEMPOTENCY_CONFLICT: (409, "The idempotency key is bound to a different request.", RetryClass.TERMINAL),
    ErrorCode.RESULT_NOT_READY: (409, "The document result is not ready.", RetryClass.RETRYABLE_WITH_BACKOFF),
    ErrorCode.SEMANTIC_VALIDATION_FAILED: (422, "The request failed semantic validation.", RetryClass.NOT_RETRYABLE),
    ErrorCode.RATE_LIMITED: (429, "The request rate is limited.", RetryClass.RETRYABLE_WITH_BACKOFF),
    ErrorCode.INTERNAL_ERROR: (500, "The service could not complete the request.", RetryClass.UNKNOWN_OR_QUARANTINED),
    ErrorCode.UPSTREAM_ERROR: (502, "A required service failed.", RetryClass.RETRYABLE_WITH_BACKOFF),
    ErrorCode.SERVICE_UNAVAILABLE: (503, "The service is temporarily unavailable.", RetryClass.RETRYABLE_WITH_BACKOFF),
    ErrorCode.REQUEST_TIMEOUT: (503, "The request outcome is not confirmed.", RetryClass.RETRY_ONLY_AFTER_RECONCILIATION),
    ErrorCode.UNSUPPORTED_CONTRACT_VERSION: (400, "The contract version is not supported.", RetryClass.NOT_RETRYABLE),
    ErrorCode.UNKNOWN_WRITE_OUTCOME: (500, "The write outcome requires reconciliation.", RetryClass.RETRY_ONLY_AFTER_RECONCILIATION),
    ErrorCode.STATE_CONFLICT: (409, "The resource state conflicts with this operation.", RetryClass.TERMINAL),
    ErrorCode.UNSUPPORTED_STATE: (500, "The resource state is not supported.", RetryClass.UNKNOWN_OR_QUARANTINED),
    ErrorCode.MALFORMED_INTERNAL_RESULT: (500, "The document result is invalid.", RetryClass.UNKNOWN_OR_QUARANTINED),
    ErrorCode.EXPIRED_OPERATION: (409, "The operation key has expired.", RetryClass.TERMINAL),
    ErrorCode.UNSUPPORTED_RESULT_TYPE: (422, "The document result type is not supported.", RetryClass.TERMINAL),
}


def public_error(
    code: ErrorCode | str,
    correlation_id: str,
    *,
    details: ErrorDetails | None = None,
) -> tuple[int, ErrorEnvelope]:
    """Create only reviewed messages/retry classes; provider text is not accepted."""

    resolved = ErrorCode(code)
    status, message, retry_class = _ERROR_POLICY[resolved]
    if details is not None and details.retry_after_seconds is not None:
        if resolved not in {ErrorCode.RATE_LIMITED, ErrorCode.SERVICE_UNAVAILABLE}:
            raise JourneyContractError("Retry-After is not meaningful for this error")
    return status, ErrorEnvelope(
        code=resolved,
        message=message,
        correlation_id=correlation_id,
        retry_class=retry_class,
        details=details,
    )


class TransactionCategory(str, Enum):
    PAYROLL = "nómina"
    TRANSFER = "transferencia"
    SPEI = "spei"
    FEE = "comisión"
    ATM_WITHDRAWAL = "retiro_atm"
    POS_PURCHASE = "compra_pos"
    SERVICE_PAYMENT = "pago_servicio"
    INTEREST = "interés"
    DIVIDEND = "dividendo"
    CHECK = "cheque"
    DIRECT_DEBIT = "domiciliación"
    OTHER = "otro"


class BankStatementWarningCode(str, Enum):
    BALANCE_RECONCILIATION_WARNING = "BALANCE_RECONCILIATION_WARNING"
    INCOMPLETE_EXTRACTION = "INCOMPLETE_EXTRACTION"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"


class BankStatementWarning(ContractModel):
    code: BankStatementWarningCode


class BankStatementProvenance(ContractModel):
    processor: Literal["bank-extract"] = "bank-extract"
    producer_schema_version: Literal["1.0"] = "1.0"
    prompt_version: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=64,
            pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
        ),
    ]
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def _aware_generated_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


class BankStatementQuality(ContractModel):
    overall_confidence: StrictFloat = Field(ge=0, le=100, allow_inf_nan=False)


NullableText = Annotated[str, StringConstraints(min_length=1, max_length=512)] | None


class Bank(ContractModel):
    name: NullableText


class BankAccount(ContractModel):
    holder: NullableText
    number_masked: Annotated[
        str, StringConstraints(pattern=r"^\*{4}[0-9]{1,4}$")
    ] | None
    clabe_masked: Annotated[
        str, StringConstraints(pattern=r"^\*{4}[0-9]{1,4}$")
    ] | None
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")] | None


class StatementPeriod(ContractModel):
    period_start: DateValue | None
    period_end: DateValue | None

    @model_validator(mode="after")
    def _ordered_period(self) -> "StatementPeriod":
        if (
            self.period_start is not None
            and self.period_end is not None
            and self.period_start > self.period_end
        ):
            raise ValueError("periodStart must not follow periodEnd")
        return self


class BankBalances(ContractModel):
    opening: StrictFloat | None = Field(allow_inf_nan=False)
    closing: StrictFloat | None = Field(allow_inf_nan=False)
    total_credits: StrictFloat | None = Field(allow_inf_nan=False)
    total_debits: StrictFloat | None = Field(allow_inf_nan=False)


class BankFees(ContractModel):
    total_fees: StrictFloat | None = Field(allow_inf_nan=False)
    iva_on_fees: StrictFloat | None = Field(allow_inf_nan=False)


class BankStatementTransaction(ContractModel):
    date: DateValue | None
    description: NullableText
    reference: NullableText
    direction: Literal["credit", "debit"]
    amount: StrictFloat | None = Field(allow_inf_nan=False)
    balance_after: StrictFloat | None = Field(allow_inf_nan=False)
    category: TransactionCategory | None


class AccountType(str, Enum):
    CHECKING = "cheques"
    SAVINGS = "ahorro"
    CREDIT = "crédito"
    INVESTMENT = "inversión"
    PAYROLL = "nómina"


class BankStatementData(ContractModel):
    bank: Bank
    account: BankAccount
    statement: StatementPeriod
    balances: BankBalances
    transactions: tuple[BankStatementTransaction, ...] = Field(max_length=10_000)
    account_type: AccountType | None
    bank_country: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] | None
    fees: BankFees | None
    interest_earned: StrictFloat | None = Field(allow_inf_nan=False)
    interest_charged: StrictFloat | None = Field(allow_inf_nan=False)
    summary_text: NullableText


class BankStatementResult(ContractModel):
    schema_version: Literal[RESULT_SCHEMA_VERSION] = RESULT_SCHEMA_VERSION
    contract_version: Literal[CONTRACT_VERSION] = CONTRACT_VERSION
    document_type: Literal["bank_statement"] = "bank_statement"
    result_type: Literal["bank_statement"] = "bank_statement"
    document_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    result_id: Annotated[
        str, StringConstraints(pattern=r"^result_[0-9a-f]{32}_v1$")
    ]
    result_version: Literal["1.0"] = "1.0"
    provenance: BankStatementProvenance
    data: BankStatementData
    warnings: tuple[BankStatementWarning, ...] = Field(default=(), max_length=16)
    quality: BankStatementQuality

    @model_validator(mode="after")
    def _identity_binding(self) -> "BankStatementResult":
        if self.result_id != f"result_{self.document_id}_v1":
            raise ValueError("resultId is not bound to documentId")
        return self


class _InternalModel(InternalArtifactModel):
    provider: Literal["bedrock"]
    modelId: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    usage: Mapping[str, Any] | None


class _InternalBank(InternalArtifactModel):
    name: NullableText = None


class _InternalAccount(InternalArtifactModel):
    holder: NullableText = None
    number: NullableText = None
    numberMasked: NullableText = None
    clabe: NullableText = None
    clabeMasked: NullableText = None
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")] | None = None


class _InternalStatement(InternalArtifactModel):
    periodStart: DateValue | None = None
    periodEnd: DateValue | None = None

    @field_validator("periodStart", "periodEnd", mode="before")
    @classmethod
    def _date_tokens_are_strings(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, str):
            raise ValueError("producer date must be a string")
        return value


class _InternalBalances(InternalArtifactModel):
    opening: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    closing: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    totalCredits: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    totalDebits: StrictFloat | None = Field(default=None, allow_inf_nan=False)


class _InternalTransaction(InternalArtifactModel):
    date: DateValue | None = None
    description: NullableText = None
    reference: NullableText = None
    direction: Literal["credit", "debit"]
    amount: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    balanceAfter: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    category: NullableText = None

    @field_validator("date", mode="before")
    @classmethod
    def _date_token_is_string(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, str):
            raise ValueError("producer date must be a string")
        return value


class _InternalFees(InternalArtifactModel):
    totalFees: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    ivaOnFees: StrictFloat | None = Field(default=None, allow_inf_nan=False)


class _InternalFieldValidation(InternalArtifactModel):
    valid: StrictBool | None = None
    present: StrictBool | None = None
    score: StrictFloat = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    issue: NullableText = None


class _InternalFieldConfidence(InternalArtifactModel):
    bankName: _InternalFieldValidation | None = None
    accountHolder: _InternalFieldValidation | None = None
    balanceReconciliation: _InternalFieldValidation | None = None
    transactionCount: _InternalFieldValidation | None = None
    periodDetected: _InternalFieldValidation | None = None


class _InternalBankStatement(InternalArtifactModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    prompt_version: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=64,
            pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
        ),
    ]
    tenant: Literal["bank"]
    documentId: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    docType: Literal["bank_statement"]
    generatedAt: datetime
    model: _InternalModel
    bank: _InternalBank
    account: _InternalAccount
    statement: _InternalStatement
    balances: _InternalBalances
    transactions: tuple[_InternalTransaction, ...] = Field(max_length=10_000)
    accountType: AccountType | None = None
    bankCountry: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] | None = None
    fees: _InternalFees | None = None
    interestEarned: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    interestCharged: StrictFloat | None = Field(default=None, allow_inf_nan=False)
    summaryText: NullableText = None
    overallConfidence: StrictFloat | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    fieldConfidence: _InternalFieldConfidence | None = None

    @field_validator("generatedAt", mode="before")
    @classmethod
    def _generated_at_is_string(cls, value: Any) -> Any:
        if not isinstance(value, str):
            raise ValueError("producer generatedAt must be a string")
        return value

    @field_validator("generatedAt")
    @classmethod
    def _aware_generated_at(cls, value: datetime) -> datetime:
        return _require_aware(value)


def _public_masked_identifier(*candidates: str | None) -> str | None:
    """Return only an irreversible display suffix, never producer mask text."""

    for candidate in candidates:
        if candidate is None:
            continue
        digits = "".join(
            character
            for character in candidate
            if character.isascii() and character.isdigit()
        )
        if digits:
            return "****" + digits[-4:]
    return None


def _safe_public_text(
    value: str | None, *sensitive_identifiers: str | None
) -> str | None:
    """Mask ASCII digit tokens with a bounded linear scan over public text."""

    if value is None:
        return None

    exact_identifier_digits = {
        "".join(
            character
            for character in candidate
            if character.isascii() and character.isdigit()
        )
        for candidate in sensitive_identifiers
        if candidate is not None
    }
    ascii_digits = frozenset("0123456789")
    masked_parts: list[str] = []
    unmasked_start = 0
    index = 0

    # Text fields are contract-bounded to 512 characters.  This scanner visits
    # every character at most twice and treats any run of non-alphanumeric
    # characters as delimiters, including arbitrary-length Unicode separators.
    while index < len(value):
        if value[index] not in ascii_digits:
            index += 1
            continue

        token_start = index
        token_digits: list[str] = []
        token_end = index
        while index < len(value):
            character = value[index]
            if character in ascii_digits:
                token_digits.append(character)
                token_end = index + 1
                index += 1
                continue
            if character.isalnum():
                break
            index += 1

        digits = "".join(token_digits)
        if len(digits) >= 8 or digits in exact_identifier_digits:
            masked_parts.append(value[unmasked_start:token_start])
            masked_parts.append("****" + digits[-4:])
            unmasked_start = token_end

    masked_parts.append(value[unmasked_start:])
    return "".join(masked_parts)


def _public_transaction_category(value: str | None) -> TransactionCategory | None:
    if value is None:
        return None
    try:
        return TransactionCategory(value)
    except ValueError:
        # Category is producer-supplied classification, not identity or money.
        # Unknown additive classifications are projected to the reviewed OTHER
        # member rather than broadening the public enum.
        return TransactionCategory.OTHER


def project_bank_statement_result(
    artifact: Mapping[str, Any], *, document_id: str
) -> BankStatementResult:
    """Validate the complete producer shape, bind identity, and remove provider data."""

    normalized_document_id = _normalize_hex_id(document_id, "documentId")
    try:
        source = _InternalBankStatement.model_validate(artifact)
    except Exception as exc:
        raise MalformedInternalResult("bank statement artifact is malformed") from exc
    if _normalize_hex_id(source.documentId, "documentId") != normalized_document_id:
        raise MalformedInternalResult("bank statement identity mismatch")
    if source.overallConfidence is None:
        raise MalformedInternalResult("bank statement quality is missing")
    if _safe_public_text(source.prompt_version) != source.prompt_version:
        raise MalformedInternalResult("bank statement provenance is malformed")

    sensitive_identifiers = (source.account.number, source.account.clabe)

    warnings: list[BankStatementWarning] = []
    confidence = source.fieldConfidence
    if source.overallConfidence < 70:
        warnings.append(BankStatementWarning(code=BankStatementWarningCode.LOW_CONFIDENCE))
    if (
        source.bank.name is None
        or source.account.holder is None
        or source.statement.periodStart is None
        or source.statement.periodEnd is None
        or not source.transactions
    ):
        warnings.append(BankStatementWarning(code=BankStatementWarningCode.INCOMPLETE_EXTRACTION))
    if (
        confidence is not None
        and confidence.balanceReconciliation is not None
        and confidence.balanceReconciliation.valid is False
    ):
        warnings.append(
            BankStatementWarning(code=BankStatementWarningCode.BALANCE_RECONCILIATION_WARNING)
        )

    return BankStatementResult(
        document_id=normalized_document_id,
        result_id=f"result_{normalized_document_id}_v1",
        provenance=BankStatementProvenance(
            prompt_version=source.prompt_version,
            generated_at=source.generatedAt,
        ),
        data=BankStatementData(
            bank=Bank(
                name=_safe_public_text(source.bank.name, *sensitive_identifiers)
            ),
            account=BankAccount(
                holder=_safe_public_text(
                    source.account.holder, *sensitive_identifiers
                ),
                number_masked=_public_masked_identifier(
                    source.account.numberMasked,
                    source.account.number,
                ),
                clabe_masked=_public_masked_identifier(
                    source.account.clabeMasked,
                    source.account.clabe,
                ),
                currency=source.account.currency,
            ),
            statement=StatementPeriod(
                period_start=source.statement.periodStart,
                period_end=source.statement.periodEnd,
            ),
            balances=BankBalances(
                opening=source.balances.opening,
                closing=source.balances.closing,
                total_credits=source.balances.totalCredits,
                total_debits=source.balances.totalDebits,
            ),
            transactions=tuple(
                BankStatementTransaction(
                    date=item.date,
                    description=_safe_public_text(
                        item.description, *sensitive_identifiers
                    ),
                    reference=_safe_public_text(
                        item.reference, *sensitive_identifiers
                    ),
                    direction=item.direction,
                    amount=item.amount,
                    balance_after=item.balanceAfter,
                    category=_public_transaction_category(
                        _safe_public_text(item.category)
                    ),
                )
                for item in source.transactions
            ),
            account_type=source.accountType,
            bank_country=source.bankCountry,
            fees=(
                BankFees(
                    total_fees=source.fees.totalFees,
                    iva_on_fees=source.fees.ivaOnFees,
                )
                if source.fees is not None
                else None
            ),
            interest_earned=source.interestEarned,
            interest_charged=source.interestCharged,
            summary_text=_safe_public_text(
                source.summaryText, *sensitive_identifiers
            ),
        ),
        warnings=tuple(warnings),
        quality=BankStatementQuality(overall_confidence=source.overallConfidence),
    )


def _normalize_hex_id(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise JourneyContractError(f"{field} is invalid")
    compact = value.replace("-", "").lower()
    if not _HEX_ID_RE.fullmatch(compact):
        raise JourneyContractError(f"{field} is invalid")
    return compact


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value


def _parse_aware(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise UnsupportedInternalState(f"{field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise UnsupportedInternalState(f"{field} is invalid") from None
    try:
        return _require_aware(parsed)
    except ValueError:
        raise UnsupportedInternalState(f"{field} is invalid") from None


__all__ = [
    "ACTOR_IDENTITY_DOMAIN",
    "API_NAMESPACE",
    "BatchCreateRequest",
    "BatchCreateResponse",
    "BatchDurableResponse",
    "BankStatementResult",
    "CANONICAL_REQUEST_DOMAIN",
    "CONTRACT_HEADER",
    "CONTRACT_VERSION",
    "DocumentCreateRequest",
    "DocumentCreateResponse",
    "DocumentDurableResponse",
    "DocumentLifecycle",
    "DocumentStatusResponse",
    "ErrorCode",
    "ErrorDetails",
    "ErrorEnvelope",
    "FailureDisposition",
    "IDEMPOTENCY_HEADER",
    "LedgerState",
    "MalformedInternalResult",
    "OperationKind",
    "OwnerScope",
    "PipelineStage",
    "ProcessingCondition",
    "ReconciliationFailureCode",
    "ReconciliationResponse",
    "RetryClass",
    "SafeFailureCode",
    "StageState",
    "SubmitDocumentRequest",
    "SubmitDocumentResponse",
    "UnsupportedInternalState",
    "UploadCapability",
    "UploadCapabilityResponse",
    "UploadRequiredHeaders",
    "adapt_internal_document_status",
    "canonical_request_digest",
    "idempotency_key_digest",
    "owner_scope_from_auth",
    "parse_strict_request",
    "project_bank_statement_result",
    "public_error",
    "require_contract_version",
    "strict_json_object",
    "validate_idempotency_key",
    "validate_lifecycle_transition",
]
