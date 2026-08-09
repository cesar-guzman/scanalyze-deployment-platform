"""Canonical `/api/v2` routes for the critical document journey."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Path, Request, status
from pydantic import ValidationError

from ...auth import AuthContext, get_auth_context
from ...authorization import (
    ROUTE_ACTION_POLICY_ATTRIBUTE,
    ROUTE_OPERATION_POLICY_ATTRIBUTE,
    require_operation,
)
from ...enterprise_authorization import (
    EnterpriseAuthorizationRuntime,
    OperationId,
    authorize_operation,
)
from ...errors import AppError
from ...journey_contract import (
    CONTRACT_HEADER,
    CONTRACT_VERSION,
    IDEMPOTENCY_HEADER,
    BatchCreateRequest,
    BatchCreateResponse,
    BankStatementResult,
    DocumentCreateRequest,
    DocumentCreateResponse,
    DocumentStatusResponse,
    ErrorEnvelope,
    JourneyContractError,
    OperationKind,
    ReconciliationResponse,
    SubmitDocumentRequest,
    SubmitDocumentResponse,
    UploadCapabilityResponse,
    parse_strict_request,
    require_contract_version,
    validate_idempotency_key,
)
from ...logging import bind_context
from ...services.journey import JourneyService


router = APIRouter(
    prefix="/api/v2",
    tags=["document-journey-v2"],
    include_in_schema=False,
)

DocumentId = Annotated[
    str,
    Path(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$"),
]
OperationPath = Annotated[
    str,
    Path(pattern=r"^(?:batches\.create|documents\.create)$"),
]


def _svc() -> JourneyService:
    return JourneyService()


def _v2_auth_context(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AuthContext:
    """Keep the rejected legacy tenant header out of the public v2 contract."""

    if len(request.headers.getlist("Authorization")) > 1:
        raise AppError(
            code="AUTHENTICATION_INVALID",
            message="Authorization header is ambiguous.",
            status_code=401,
            details={},
        )
    if request.headers.getlist("X-Tenant-Id"):
        raise AppError(
            code="AUTHORIZATION_DENIED",
            message="Client-supplied identity headers are not allowed.",
            status_code=403,
            details={},
        )
    return get_auth_context(
        request=request,
        authorization=authorization,
        x_tenant_id=None,
    )


_CREATE_BATCH_ACCESS = require_operation(
    OperationId.BATCHES_CREATE,
    auth_dependency=_v2_auth_context,
)
_CREATE_DOCUMENT_ACCESS = require_operation(
    OperationId.DOCUMENTS_CREATE,
    auth_dependency=_v2_auth_context,
)
_SUBMIT_DOCUMENT_ACCESS = require_operation(
    OperationId.DOCUMENTS_SUBMIT,
    auth_dependency=_v2_auth_context,
)
_READ_DOCUMENT_ACCESS = require_operation(
    OperationId.DOCUMENTS_READ_METADATA,
    auth_dependency=_v2_auth_context,
)
_READ_FULL_RESULT_ACCESS = require_operation(
    OperationId.RESULTS_READ_FULL,
    auth_dependency=_v2_auth_context,
)


def _contract_context(
    request: Request,
    contract_version: Annotated[
        str,
        Header(
            alias=CONTRACT_HEADER,
            min_length=len(CONTRACT_VERSION),
            max_length=len(CONTRACT_VERSION),
            pattern=r"^scanalyze\.document-journey\.v1$",
            description=(
                "Exact document-journey contract. Missing or unsupported values "
                "are rejected; there is no downgrade."
            ),
            json_schema_extra={"const": CONTRACT_VERSION},
        ),
    ],
    correlation_id: Annotated[
        str | None,
        Header(
            alias="X-Correlation-ID",
            min_length=8,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
            description=(
                "Optional opaque diagnostic reference. It never establishes "
                "identity or ownership."
            ),
        ),
    ] = None,
) -> str:
    if len(request.headers.getlist(CONTRACT_HEADER)) != 1:
        raise AppError(
            code="UNSUPPORTED_CONTRACT_VERSION",
            message="Contract version is unsupported.",
            status_code=400,
            details={"field": CONTRACT_HEADER},
        )
    if len(request.headers.getlist("X-Correlation-ID")) > 1:
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Correlation header is invalid.",
            status_code=400,
            details={"field": "X-Correlation-ID"},
        )
    del correlation_id  # Middleware hashes it; it never establishes authority.
    try:
        return require_contract_version(contract_version)
    except JourneyContractError as error:
        raise AppError(
            code="UNSUPPORTED_CONTRACT_VERSION",
            message="Contract version is unsupported.",
            status_code=400,
            details={"field": CONTRACT_HEADER},
        ) from error


def _idempotency_key(
    request: Request,
    value: Annotated[
        str,
        Header(
            alias=IDEMPOTENCY_HEADER,
            min_length=36,
            max_length=36,
            pattern=(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
            description=(
                "Opaque canonical UUID. The raw value is never persisted or logged."
            ),
            json_schema_extra={"format": "uuid"},
        ),
    ],
) -> str:
    if len(request.headers.getlist(IDEMPOTENCY_HEADER)) != 1:
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Idempotency key is invalid.",
            status_code=400,
            details={"field": IDEMPOTENCY_HEADER},
        )
    try:
        return validate_idempotency_key(value)
    except JourneyContractError as error:
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Idempotency key is invalid.",
            status_code=400,
            details={"field": IDEMPOTENCY_HEADER},
        ) from error


def _parse_operation(value: str) -> OperationKind:
    try:
        return OperationKind(value)
    except ValueError as error:
        raise AppError(
            code="SEMANTIC_VALIDATION_FAILED",
            message="Operation is unsupported.",
            status_code=422,
            details={"field": "operation"},
        ) from error


def _reconciliation_access(
    request: Request,
    operation: OperationPath,
    auth: AuthContext = Depends(_v2_auth_context),
) -> AuthContext:
    operation_kind = _parse_operation(operation)
    operation_id = {
        OperationKind.BATCH_CREATE: OperationId.BATCHES_CREATE,
        OperationKind.DOCUMENT_CREATE: OperationId.DOCUMENTS_CREATE,
    }[operation_kind]
    runtime = getattr(
        request.app.state,
        "enterprise_authorization_runtime",
        None,
    )
    if not isinstance(runtime, EnterpriseAuthorizationRuntime):
        runtime = None
    return authorize_operation(auth, operation_id, runtime=runtime)


setattr(_reconciliation_access, ROUTE_ACTION_POLICY_ATTRIBUTE, frozenset({"write"}))
setattr(
    _reconciliation_access,
    ROUTE_OPERATION_POLICY_ATTRIBUTE,
    frozenset({OperationId.BATCHES_CREATE, OperationId.DOCUMENTS_CREATE}),
)


def _ensure_json_media_type(request: Request) -> None:
    if len(request.headers.getlist("Content-Type")) != 1:
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Content-Type must be application/json.",
            status_code=400,
            details={"field": "body"},
        )
    media_type = (
        request.headers.get("content-type", "")
        .split(";", 1)[0]
        .strip()
        .lower()
    )
    if media_type != "application/json":
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Content-Type must be application/json.",
            status_code=400,
            details={"field": "body"},
        )


async def _closed_body(request: Request, model: type[Any]) -> Any:
    _ensure_json_media_type(request)
    raw = await request.body()
    try:
        return parse_strict_request(raw, model)
    except JourneyContractError as error:
        raise AppError(
            code="MALFORMED_REQUEST",
            message="Request body is malformed.",
            status_code=400,
            details={"field": "body"},
        ) from error
    except ValidationError as error:
        raise AppError(
            code="SEMANTIC_VALIDATION_FAILED",
            message="Request body is invalid.",
            status_code=422,
            details={"field": "body"},
        ) from error


async def _batch_body(request: Request) -> BatchCreateRequest:
    return await _closed_body(request, BatchCreateRequest)


async def _document_body(request: Request) -> DocumentCreateRequest:
    return await _closed_body(request, DocumentCreateRequest)


async def _submit_body(request: Request) -> SubmitDocumentRequest:
    return await _closed_body(request, SubmitDocumentRequest)


_CORRELATION_RESPONSE_HEADER = {
    "required": True,
    "description": "Safe opaque diagnostic reference for support correlation.",
    "schema": {"type": "string", "pattern": r"^ref_[0-9a-f]{32}$"},
}
_RETRY_AFTER_RESPONSE_HEADER = {
    "required": False,
    "description": (
        "Bounded whole seconds before another allowed attempt. Emitted only when "
        "the error retryClass is RETRYABLE_WITH_BACKOFF and a server delay is "
        "authoritative."
    ),
    "x-emission-policy": (
        "omit for retry-only-after-reconciliation, terminal, not-retryable and "
        "unknown outcomes"
    ),
    "schema": {"type": "integer", "minimum": 1, "maximum": 3600},
}
_ERROR_RESPONSES = {}
for _status_code in (400, 401, 403, 404, 409, 422, 429, 500, 502, 503):
    _headers = {"X-Correlation-ID": _CORRELATION_RESPONSE_HEADER}
    if _status_code in {429, 503}:
        _headers["Retry-After"] = _RETRY_AFTER_RESPONSE_HEADER
    _ERROR_RESPONSES[_status_code] = {
        "model": ErrorEnvelope,
        "headers": _headers,
    }


def _responses(
    success_status: int,
    *,
    include_not_found: bool = True,
) -> dict[int, dict[str, Any]]:
    responses = {
        success_status: {
            "headers": {"X-Correlation-ID": _CORRELATION_RESPONSE_HEADER}
        },
        **_ERROR_RESPONSES,
    }
    if not include_not_found:
        responses.pop(404)
    return responses


@router.post(
    "/batches",
    response_model=BatchCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses=_responses(status.HTTP_201_CREATED, include_not_found=False),
    operation_id="createBatchV2",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "maxProperties": 0,
                        "properties": {},
                    }
                }
            },
        }
    },
)
def create_batch(
    _contract: str = Depends(_contract_context),
    idempotency_key: str = Depends(_idempotency_key),
    request_body: BatchCreateRequest = Depends(_batch_body),
    auth: AuthContext = Depends(_CREATE_BATCH_ACCESS),
    service: JourneyService = Depends(_svc),
) -> BatchCreateResponse:
    del _contract
    return service.create_batch(
        auth=auth,
        idempotency_key=idempotency_key,
        request=request_body,
    )


@router.post(
    "/documents",
    response_model=DocumentCreateResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses=_responses(status.HTTP_201_CREATED),
    operation_id="createDocumentV2",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["contentType"],
                        "properties": {
                            "filename": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                                "pattern": (
                                    r"^(?!\s*\.{1,2}\s*$)(?=.*\S)[^\x00-\x1f\x7f/\\]{1,128}$"
                                ),
                            },
                            "contentType": {
                                "type": "string",
                                "enum": [
                                    "application/pdf",
                                    "image/jpeg",
                                    "image/png",
                                    "image/tiff",
                                ],
                            },
                            "contentLength": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 536870912,
                            },
                            "batchId": {
                                "type": "string",
                                "pattern": "^[0-9a-f]{32}$",
                            },
                        },
                    }
                }
            },
        }
    },
)
def create_document(
    _contract: str = Depends(_contract_context),
    idempotency_key: str = Depends(_idempotency_key),
    request_body: DocumentCreateRequest = Depends(_document_body),
    auth: AuthContext = Depends(_CREATE_DOCUMENT_ACCESS),
    service: JourneyService = Depends(_svc),
) -> DocumentCreateResponse:
    del _contract
    return service.create_document(
        auth=auth,
        idempotency_key=idempotency_key,
        request=request_body,
    )


@router.post(
    "/documents/{documentId}/submit",
    response_model=SubmitDocumentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_responses(status.HTTP_202_ACCEPTED),
    operation_id="submitDocumentV2",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "stage": {"type": "string", "const": "ingest"}
                        },
                    }
                }
            },
        }
    },
)
def submit_document(
    documentId: DocumentId,
    _contract: str = Depends(_contract_context),
    request_body: SubmitDocumentRequest = Depends(_submit_body),
    auth: AuthContext = Depends(_SUBMIT_DOCUMENT_ACCESS),
    service: JourneyService = Depends(_svc),
) -> SubmitDocumentResponse:
    del _contract
    bind_context(documentId=documentId)
    return service.submit_document(
        auth=auth,
        document_id=documentId,
        request=request_body,
    )


@router.get(
    "/documents/{documentId}",
    response_model=DocumentStatusResponse,
    response_model_exclude_none=True,
    responses=_responses(status.HTTP_200_OK),
    operation_id="getDocumentStatusV2",
)
def get_document_status(
    documentId: DocumentId,
    _contract: str = Depends(_contract_context),
    auth: AuthContext = Depends(_READ_DOCUMENT_ACCESS),
    service: JourneyService = Depends(_svc),
) -> DocumentStatusResponse:
    del _contract
    bind_context(documentId=documentId)
    return service.get_document_status(auth=auth, document_id=documentId)


@router.post(
    "/documents/{documentId}/upload-capabilities",
    response_model=UploadCapabilityResponse,
    responses=_responses(status.HTTP_200_OK),
    operation_id="refreshDocumentUploadCapabilityV2",
)
def refresh_upload_capability(
    documentId: DocumentId,
    _contract: str = Depends(_contract_context),
    auth: AuthContext = Depends(_CREATE_DOCUMENT_ACCESS),
    service: JourneyService = Depends(_svc),
) -> UploadCapabilityResponse:
    del _contract
    bind_context(documentId=documentId)
    return service.refresh_upload_capability(
        auth=auth,
        document_id=documentId,
    )


@router.post(
    "/operations/{operation}/reconciliation",
    response_model=ReconciliationResponse,
    response_model_exclude_none=True,
    responses=_responses(status.HTTP_200_OK),
    operation_id="reconcileDocumentJourneyOperationV2",
)
def reconcile_operation(
    operation: OperationPath,
    _contract: str = Depends(_contract_context),
    idempotency_key: str = Depends(_idempotency_key),
    auth: AuthContext = Depends(_reconciliation_access),
    service: JourneyService = Depends(_svc),
) -> ReconciliationResponse:
    del _contract
    return service.reconcile(
        auth=auth,
        operation=_parse_operation(operation),
        idempotency_key=idempotency_key,
    )


@router.get(
    "/documents/{documentId}/result",
    response_model=BankStatementResult,
    responses=_responses(status.HTTP_200_OK),
    operation_id="getDocumentResultV2",
)
def get_result(
    documentId: DocumentId,
    _contract: str = Depends(_contract_context),
    auth: AuthContext = Depends(_READ_FULL_RESULT_ACCESS),
    service: JourneyService = Depends(_svc),
) -> BankStatementResult:
    del _contract
    bind_context(documentId=documentId)
    return service.get_result(auth=auth, document_id=documentId)


__all__ = ["_svc", "router"]
