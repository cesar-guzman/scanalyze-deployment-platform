import logging
import re
import structlog
import sys
from structlog.contextvars import bind_contextvars


def safe_error_details(exc: BaseException) -> dict:
    """Return validation diagnostics without messages, inputs, or payload values."""
    details = {"errorType": type(exc).__name__}
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

def setup_logging():
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            sanitize_exception_info,
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    log_level = logging.INFO
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

def get_logger(name: str):
    return structlog.get_logger(name)

def bind_context(**kwargs):
    mapping = {
        "documentId": "documentId",
        "correlationId": "correlationId",
        "traceId": "traceId",
        "uploaderUserId": "uploaderUserId",
        "customerStack": "customerStack",
        "route": "route",
        "tenant": "tenant",
        "stage": "stage",
    }
    normalized = {}
    for k, v in kwargs.items():
        nk = mapping.get(k, k)
        if v is not None:
            normalized[nk] = v
    if normalized:
        bind_contextvars(**normalized)
