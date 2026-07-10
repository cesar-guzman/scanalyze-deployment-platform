from __future__ import annotations

import logging
import re
import sys
from typing import Any, Dict, Optional

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars


def safe_error_details(exc: BaseException) -> Dict[str, Any]:
    """Return stable diagnostics without exception messages or input values."""
    details: Dict[str, Any] = {"errorType": type(exc).__name__}
    errors_method = getattr(exc, "errors", None)
    if callable(errors_method):
        try:
            errors = errors_method(
                include_input=False,
                include_context=False,
                include_url=False,
            )
        except TypeError:
            errors = errors_method()
        locations = []
        for error in errors:
            parts = []
            for part in error.get("loc", ()):
                value = str(part)
                parts.append(value if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) else "<field>")
            location = ".".join(parts) or "<root>"
            if location not in locations:
                locations.append(location)
        details["errorCount"] = len(errors)
        details["invalidFields"] = locations[:20]
    elif hasattr(exc, "lineno") and hasattr(exc, "colno"):
        details["line"] = exc.lineno
        details["column"] = exc.colno
    return details


def sanitize_exception_info(logger, method_name, event_dict):
    """Replace traceback-bearing structlog fields with a stable exception type."""
    exc_info = event_dict.pop("exc_info", None)
    event_dict.pop("exception", None)
    if exc_info:
        exc_type = exc_info[0] if isinstance(exc_info, tuple) else sys.exc_info()[0]
        if exc_type is not None:
            event_dict.setdefault("errorType", exc_type.__name__)
    return event_dict

def configure_logging(log_level: str, service_name: str, env: str) -> None:
    """
    Configura logging estructurado JSON (stdout) usando structlog.
    """
    level = getattr(logging, (log_level or "INFO").upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    # structlog processors
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            sanitize_exception_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )

    # Campos base fijos en todo log
    bind_contextvars(service=service_name, env=env)

def get_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger()

def bind_context(**kwargs: Any) -> None:
    """
    Adjunta campos al contexto de logging.
    Requeridos por el contrato operativo: documentId, stage, tenant, traceId, requestId
    (se setean cuando aplique).
    """
    # Normaliza nombres esperados
    mapping = {
        "documentId": "documentId",
        "docId": "documentId",
        "document_id": "documentId",
        "stage": "stage",
        "tenant": "tenant",
        "tenantId": "tenant",
        "traceId": "traceId",
        "requestId": "requestId",
        "correlationId": "correlationId",
        "uploaderUserId": "uploaderUserId",
        "customerStack": "customerStack",
        "route": "route",
    }
    normalized: Dict[str, Any] = {}
    for k, v in kwargs.items():
        nk = mapping.get(k, k)
        if v is None:
            continue
        normalized[nk] = v
    if normalized:
        bind_contextvars(**normalized)

def clear_context() -> None:
    clear_contextvars()
