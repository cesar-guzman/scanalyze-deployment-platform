from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging import get_logger, safe_error_details


def _is_v2(request: Request) -> bool:
    return request.url.path == "/api/v2" or request.url.path.startswith("/api/v2/")


def _v2_correlation_id() -> str:
    from structlog.contextvars import get_contextvars

    value = get_contextvars().get("correlationId")
    if isinstance(value, str) and re.fullmatch(r"ref_[0-9a-f]{32}", value):
        return value
    material = value if isinstance(value, str) and value else uuid.uuid4().hex
    return "ref_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _v2_error_code(request: Request, exc: AppError) -> str:
    from .journey_contract import ErrorCode

    exact = {member.value for member in ErrorCode}
    if exc.code in exact:
        return exc.code
    if exc.status_code == 401:
        return (
            "AUTHENTICATION_INVALID"
            if request.headers.get("authorization")
            else "AUTHENTICATION_REQUIRED"
        )
    if exc.status_code == 403:
        return "AUTHORIZATION_DENIED"
    if exc.status_code == 404:
        return "NOT_FOUND"
    if exc.status_code == 409:
        return "STATE_CONFLICT" if "STATE_CONFLICT" in exact else "UNSUPPORTED_STATE"
    if exc.status_code == 422:
        return "SEMANTIC_VALIDATION_FAILED"
    if exc.status_code == 429:
        return "RATE_LIMITED"
    if exc.status_code == 502:
        return "UPSTREAM_ERROR"
    if exc.status_code == 503:
        return "SERVICE_UNAVAILABLE"
    return "INTERNAL_ERROR"


def _v2_response(request: Request, exc: AppError) -> JSONResponse:
    from .journey_contract import (
        ErrorDetails,
        ErrorField,
        JourneyContractError,
        OperationKind,
        public_error,
    )

    resolved_code = _v2_error_code(request, exc)
    raw_details = exc.details if isinstance(exc.details, dict) else {}
    field = raw_details.get("field")
    operation = raw_details.get("operation")
    retry_after = exc.retry_after_seconds or raw_details.get("retryAfterSeconds")
    details = None
    parsed_retry = None
    correlation_id = _v2_correlation_id()
    try:
        try:
            parsed_field = ErrorField(field) if isinstance(field, str) else None
        except ValueError:
            parsed_field = None
        try:
            parsed_operation = (
                OperationKind(operation) if isinstance(operation, str) else None
            )
        except ValueError:
            parsed_operation = None
        # Retry-After is part of the public wire contract only for bounded
        # rate limiting and service-unavailable backoff.  Provider hints on a
        # different error class are ignored rather than reflected.
        if resolved_code in {"RATE_LIMITED", "SERVICE_UNAVAILABLE"}:
            parsed_retry = (
                retry_after
                if isinstance(retry_after, int)
                and not isinstance(retry_after, bool)
                and 1 <= retry_after <= 3600
                else None
            )
        if parsed_field is not None or parsed_operation is not None or parsed_retry is not None:
            details = ErrorDetails(
                field=parsed_field,
                operation=parsed_operation,
                retry_after_seconds=parsed_retry,
            )
        status_code, envelope = public_error(
            resolved_code,
            correlation_id,
            details=details,
        )
    except (ValueError, JourneyContractError):
        status_code, envelope = public_error(
            "INTERNAL_ERROR",
            correlation_id,
        )
        parsed_retry = None
    headers = {"X-Correlation-ID": envelope.correlation_id}
    if parsed_retry is not None:
        headers["Retry-After"] = str(parsed_retry)
    return JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        headers=headers,
    )


def _v2_validation_error(exc: RequestValidationError) -> AppError:
    """Map framework validation failures onto the reviewed v2 policy.

    Required negotiation/idempotency headers are transport contract errors,
    not FastAPI's default 422 body-validation response.  The remaining closed
    path/body model failures retain semantic-validation behavior.
    """

    issues = exc.errors()

    def has_location(location: str, field: str, *, missing_only: bool = False) -> bool:
        for issue in issues:
            raw_location = issue.get("loc")
            if not isinstance(raw_location, (list, tuple)) or len(raw_location) < 2:
                continue
            if str(raw_location[0]).lower() != location.lower():
                continue
            if str(raw_location[1]).lower() != field.lower():
                continue
            if not missing_only or issue.get("type") == "missing":
                return True
        return False

    if has_location(
        "header",
        "X-Scanalyze-Contract-Version",
    ):
        return AppError(
            code="UNSUPPORTED_CONTRACT_VERSION",
            message="Contract version is required.",
            status_code=400,
            details={"field": "X-Scanalyze-Contract-Version"},
        )
    if has_location("header", "Idempotency-Key", missing_only=True):
        return AppError(
            code="MALFORMED_REQUEST",
            message="Idempotency key is required.",
            status_code=400,
            details={"field": "Idempotency-Key"},
        )
    if any(
        isinstance(issue.get("loc"), (list, tuple))
        and issue["loc"]
        and str(issue["loc"][0]).lower() == "header"
        for issue in issues
    ):
        return AppError(
            code="MALFORMED_REQUEST",
            message="Request header is invalid.",
            status_code=400,
            details={},
        )

    field = "body"
    for public_field in ("documentId", "operation"):
        if has_location("path", public_field):
            field = public_field
            break
    return AppError(
        code="SEMANTIC_VALIDATION_FAILED",
        message="Request validation failed.",
        status_code=422,
        details={"field": field},
    )


@dataclass
class AppError(Exception):
    code: str
    message: str
    status_code: int = 400
    details: Optional[Dict[str, Any]] = None
    # Public v2 handlers use these closed hints; legacy v1 envelopes ignore
    # them.  Values are never populated from provider exception text.
    retry_class: Optional[str] = None
    retry_after_seconds: Optional[int] = None


def error_envelope(
    code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "details": details or {},
    }


def register_exception_handlers(app: FastAPI) -> None:
    logger = get_logger()

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        # No loguear PII ni body. Solo contexto técnico.
        logger.warning(
            "app_error",
            httpStatus=exc.status_code,
            errorCode=exc.code,
        )
        if _is_v2(request):
            return _v2_response(request, exc)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        details = safe_error_details(exc)
        logger.info("validation_error", httpStatus=422, **details)
        if _is_v2(request):
            return _v2_response(request, _v2_validation_error(exc))
        return JSONResponse(
            status_code=422,
            content=error_envelope(
                "VALIDATION_ERROR",
                "Request validation failed",
                details,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Normaliza a nuestro envelope
        code = "HTTP_ERROR"
        logger.info("http_exception", httpStatus=exc.status_code)
        if _is_v2(request):
            code = {
                401: "AUTHENTICATION_REQUIRED",
                403: "AUTHORIZATION_DENIED",
                404: "NOT_FOUND",
                405: "MALFORMED_REQUEST",
                429: "RATE_LIMITED",
                503: "SERVICE_UNAVAILABLE",
            }.get(exc.status_code, "MALFORMED_REQUEST")
            return _v2_response(
                request,
                AppError(
                    code=code,
                    message="HTTP request failed.",
                    status_code=exc.status_code,
                    details={},
                )
            )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(
                code,
                "HTTP request failed",
                {"status_code": exc.status_code},
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Error interno: no filtramos stack al cliente.
        logger.error("unhandled_exception", **safe_error_details(exc))
        if _is_v2(request):
            return _v2_response(
                request,
                AppError(
                    code="INTERNAL_ERROR",
                    message="Internal server error.",
                    status_code=500,
                    details={},
                )
            )
        return JSONResponse(
            status_code=500,
            content=error_envelope("INTERNAL_ERROR", "Internal server error", {}),
        )
