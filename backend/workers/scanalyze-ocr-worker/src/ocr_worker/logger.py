import logging
import os
import json
import contextvars
import re
from datetime import datetime, timezone

_log_context = contextvars.ContextVar('scanalyze_log_context', default={})

# ── Centralised allowlist ────────────────────────────────────────────
# Every field name that may appear in structured log output must be listed
# here.  Unknown fields are **dropped fail-closed** — they never reach
# the serializer.  The list was reconciled against every production call
# site in the OCR worker as of GUG-105.
#
# bind_context:  documentId, correlationId, traceId, tenant, stage
# log_event:     signal, queue, queue_name, message_id, receive_count,
#                messageId, receiveCount, documentId, jobId, textractJobId,
#                document_route, downstream_message_id, delay, attempt,
#                status, state, next_stage, reason, errorType, errorCount,
#                invalidFields
# logger extra:  errorType, parameterCount, event
# safe_error_details: errorType, errorCount, invalidFields, line, column
_ALLOWED_FIELDS: frozenset = frozenset({
    # Correlation / tracing
    "correlationId",
    "traceId",
    # Document identity
    "documentId",
    # Tenant / stage
    "tenant",
    "stage",
    # Event descriptor
    "event",
    # Message identity
    "message_id",
    "messageId",
    "downstream_message_id",
    # Queue / routing
    "queue",
    "queue_name",
    "next_stage",
    "document_route",
    # Job / attempt
    "jobId",
    "textractJobId",
    "attempt",
    "delay",
    "receive_count",
    "receiveCount",
    # State
    "status",
    "state",
    "signal",
    "reason",
    # Error diagnostics
    "errorType",
    "errorCount",
    "line",
    "column",
    "parameterCount",
    # safe_error_details bounded list — validated separately
    "invalidFields",
})

# Maximum length for any scalar string value emitted to logs.
_MAX_VALUE_LENGTH = 1024

# Characters that must never appear in log values (control chars except tab).
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _sanitize_scalar(value: object) -> object:
    """Coerce a single value to a safe log-emittable scalar, or return None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        cleaned = _CONTROL_CHAR_RE.sub('', value)
        if len(cleaned) > _MAX_VALUE_LENGTH:
            cleaned = cleaned[:_MAX_VALUE_LENGTH] + "…[truncated]"
        return cleaned
    # Arbitrary objects (dicts, lists, custom classes) are dropped.
    return None


def _sanitize_invalid_fields(value: object) -> object:
    """Validate invalidFields: must be a bounded list of safe short strings."""
    if not isinstance(value, (list, tuple)):
        return None
    safe = []
    for item in value[:20]:
        if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.<>-]{1,64}", item):
            safe.append(item)
    return safe if safe else None


def _sanitize_log_fields(values: dict, *, source: str) -> dict:
    """Canonical fail-closed sanitizer for all structured log metadata.

    Only fields present in _ALLOWED_FIELDS are emitted.  Values must be
    safe scalars; dicts, lists (except invalidFields), and custom objects
    are dropped silently.

    Parameters
    ----------
    values : dict
        Raw key-value pairs from the caller.
    source : str
        One of "context", "event", or "extra" — used only for diagnostics.

    Returns
    -------
    dict
        Sanitized dictionary with only allowed, safe scalar values.
    """
    sanitized = {}
    for key, value in values.items():
        if key not in _ALLOWED_FIELDS:
            continue  # fail-closed: unknown keys are silently dropped
        if key == "invalidFields":
            safe_value = _sanitize_invalid_fields(value)
        else:
            safe_value = _sanitize_scalar(value)
        if safe_value is not None:
            sanitized[key] = safe_value
    return sanitized


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

def bind_context(**kwargs):
    """Bind structured context for the current async scope.

    Only allowed fields are stored; unknown keys are dropped fail-closed.
    Values are sanitized before storage (defense in depth: also sanitized
    at serialization time in JSONFormatter).
    """
    ctx = _log_context.get().copy()
    sanitized = _sanitize_log_fields(kwargs, source="context")
    ctx.update(sanitized)
    _log_context.set(ctx)


def clear_context():
    _log_context.set({})

class JSONFormatter(logging.Formatter):
    def __init__(self, tenant: str, stage: str):
        super().__init__()
        self.tenant = tenant
        self.stage = stage
        self.env = os.environ.get('SCANALYZE_ENV', '').strip()
        if not self.env:
            raise RuntimeError("SCANALYZE_ENV is required")

    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "env": self.env,
            "tenant": self.tenant,
            "stage": self.stage,
            "message": record.getMessage()
        }

        # Context fields — already sanitized at bind_context() but we
        # re-sanitize as defense-in-depth.
        ctx = _log_context.get()
        sanitized_ctx = _sanitize_log_fields(dict(ctx), source="context")
        for k, v in sanitized_ctx.items():
            log_record[k] = v

        if record.exc_info and record.exc_info[0] is not None:
            # Tracebacks include exception messages, which can contain document data.
            log_record["errorType"] = record.exc_info[0].__name__

        # Extra fields from LogRecord — fail-closed through the sanitizer.
        _internal_keys = frozenset({
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "module", "msecs",
            "message", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
            "taskName",
        })
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in _internal_keys
        }
        sanitized_extras = _sanitize_log_fields(extras, source="extra")
        for k, v in sanitized_extras.items():
            log_record[k] = v

        return json.dumps(log_record)

def setup_logging():
    log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()

    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler()
    tenant = os.environ.get('SCANALYZE_TENANT', '').strip()
    if not tenant:
        raise RuntimeError("SCANALYZE_TENANT is required")
    service = os.environ.get("SERVICE_NAME", os.environ.get("WORKER_MODE", "scanalyze-ocr-worker").lower())
    handler.setFormatter(JSONFormatter(tenant=tenant, stage=service))

    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    root_logger.addHandler(handler)

    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def get_logger(name: str):
    return logging.getLogger(name)

def log_event(event_name: str, **kwargs):
    """Emit a structured event with only allowed metadata.

    All keyword arguments are sanitized through the canonical allowlist
    before being attached to the log record.
    """
    logger = logging.getLogger('ocr_worker.structured')

    safe_kwargs = _sanitize_log_fields(kwargs, source="event")

    logger.info(event_name, extra={"event": event_name, **safe_kwargs})
