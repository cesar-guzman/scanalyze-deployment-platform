from __future__ import annotations

import time
import uuid
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .logging import bind_context, clear_context, get_logger

def _first_header(request: Request, names: list[str]) -> Optional[str]:
    for n in names:
        v = request.headers.get(n)
        if v:
            return v
    return None

class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    - Genera/propaga requestId
    - Captura traceId (best-effort)
    - Request logging JSON (sin body)
    - Limpia contextvars al final
    """

    def __init__(self, app, service_name: str = "scanalyze-ingest-api"):
        super().__init__(app)
        self.logger = get_logger()
        self.service_name = service_name

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()

        request_id = _first_header(
            request,
            [
                "x-request-id",
                "x-amzn-requestid",
                "x-amz-request-id",
            ],
        ) or str(uuid.uuid4())

        correlation_id = _first_header(
            request,
            [
                "x-correlation-id",
            ],
        ) or request_id

        trace_id = _first_header(
            request,
            [
                "x-amzn-trace-id",
                "traceparent",
                "x-b3-traceid",
            ],
        ) or request_id

        # Bind base request context (tenant/doc/stage se adjuntan en handlers)
        bind_context(requestId=request_id, traceId=trace_id, correlationId=correlation_id)

        # Respuesta siempre con correlación
        try:
            response: Response = await call_next(request)
        except Exception:
            # Excepción se maneja por handlers; igual logueamos timing
            duration_ms = int((time.time() - start) * 1000)
            self.logger.info(
                "request_failed",
                method=request.method,
                path=str(request.url.path),
                durationMs=duration_ms,
            )
            clear_context()
            raise

        duration_ms = int((time.time() - start) * 1000)

        response.headers["x-request-id"] = request_id
        response.headers["x-trace-id"] = trace_id
        response.headers["x-correlation-id"] = correlation_id

        self.logger.info(
            "request_completed",
            method=request.method,
            path=str(request.url.path),
            statusCode=response.status_code,
            durationMs=duration_ms,
        )

        clear_context()
        return response
