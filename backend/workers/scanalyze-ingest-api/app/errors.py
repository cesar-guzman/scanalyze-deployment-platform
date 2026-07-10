from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging import get_logger, safe_error_details

@dataclass
class AppError(Exception):
    code: str
    message: str
    status_code: int = 400
    details: Optional[Dict[str, Any]] = None

def error_envelope(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = safe_error_details(exc)
        logger.info("validation_error", httpStatus=422, **details)
        return JSONResponse(
            status_code=422,
            content=error_envelope("VALIDATION_ERROR", "Request validation failed", details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Normaliza a nuestro envelope
        code = "HTTP_ERROR"
        logger.info("http_exception", httpStatus=exc.status_code)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(code, "HTTP request failed", {"status_code": exc.status_code}),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Error interno: no filtramos stack al cliente.
        logger.error("unhandled_exception", **safe_error_details(exc))
        return JSONResponse(
            status_code=500,
            content=error_envelope("INTERNAL_ERROR", "Internal server error", {}),
        )
