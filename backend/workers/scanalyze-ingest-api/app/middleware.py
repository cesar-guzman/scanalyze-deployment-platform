from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .logging import bind_context, clear_context, get_logger

_ROUTE_TEMPLATE_PATTERN = re.compile(r"^/[A-Za-z0-9_./{}-]{0,255}$")


def request_route_template(request: Request) -> str:
    """Return only the code-owned route template, never a dynamic raw path."""
    scope = getattr(request, "scope", None)
    route = scope.get("route") if isinstance(scope, dict) else None
    template = getattr(route, "path", None)
    if (
        isinstance(template, str)
        and _ROUTE_TEMPLATE_PATTERN.fullmatch(template)
    ):
        return template
    return "unmatched"


def _first_header(request: Request, names: list[str]) -> Optional[str]:
    for n in names:
        v = request.headers.get(n)
        if v:
            return v
    return None


def _opaque_reference(external_value: Optional[str]) -> str:
    """Return a bounded opaque reference without propagating external input."""
    if external_value is not None and external_value.strip():
        reference = hashlib.sha256(external_value.encode("utf-8")).hexdigest()[:32]
    else:
        reference = uuid.uuid4().hex
    return f"ref_{reference}"


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
        # Never inherit request-local identifiers from a reused async context.
        clear_context()

        request_id = _opaque_reference(
            _first_header(
                request,
                [
                    "x-request-id",
                    "x-amzn-requestid",
                    "x-amz-request-id",
                ],
            )
        )

        correlation_id = _opaque_reference(
            _first_header(
                request,
                [
                    "x-correlation-id",
                ],
            )
        )

        trace_id = _opaque_reference(
            _first_header(
                request,
                [
                    "x-amzn-trace-id",
                    "traceparent",
                    "x-b3-traceid",
                ],
            )
        )

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
                route=request_route_template(request),
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
            route=request_route_template(request),
            statusCode=response.status_code,
            durationMs=duration_ms,
        )

        clear_context()
        return response
