import logging
import os
import json
import contextvars
import re
import math
from datetime import datetime, timezone

_log_context = contextvars.ContextVar('scanalyze_log_context', default={})

_SOURCE_PERMISSIONS = {
    "context": frozenset({"correlationId", "traceId", "documentId", "tenant", "stage"}),
    "event": frozenset({
        "signal", "queue", "queue_name", "message_id", "receive_count",
        "messageId", "receiveCount", "documentId", "jobId", "textractJobId",
        "document_route", "downstream_message_id", "delay", "attempt",
        "status", "state", "next_stage", "reason", "errorType", "errorCount",
        "invalidFields"
    }),
    "extra": frozenset({"event", "errorType", "parameterCount"})
}

_MAX_VALUE_LENGTH = 1024
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def _sanitize_scalar(value: object, field: str = None) -> object:
    if value is None:
        return None
    if type(value) is bool:
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        if type(value) is not bool and isinstance(value, int):
            if field in ("errorCount", "parameterCount", "attempt", "receiveCount", "receive_count", "delay"):
                if value < 0:
                    return None
        return value
    if isinstance(value, str):
        cleaned = _CONTROL_CHAR_RE.sub('', value)
        if len(cleaned) > _MAX_VALUE_LENGTH:
            suffix = "…[truncated]"
            cleaned = cleaned[:_MAX_VALUE_LENGTH - len(suffix)] + suffix
        return cleaned
    return None

def _sanitize_invalid_fields(value: object) -> object:
    if not isinstance(value, (list, tuple)):
        return None
    safe = []
    for item in value[:20]:
        if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.<>-]{1,64}", item):
            safe.append(item)
    return safe if safe else None

def _sanitize_log_value(field: str, value: object, *, source: str) -> object:
    if field in ("correlationId", "traceId"):
        if not isinstance(value, str):
            return None
        if re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$", value):
            return value
        return None
    if field == "invalidFields":
        return _sanitize_invalid_fields(value)
    return _sanitize_scalar(value, field=field)

def _sanitize_log_fields(values: dict, *, source: str) -> dict:
    sanitized = {}
    allowed = _SOURCE_PERMISSIONS.get(source, frozenset())
    for key, value in values.items():
        if key not in allowed:
            continue
        safe_value = _sanitize_log_value(key, value, source=source)
        if safe_value is not None:
            sanitized[key] = safe_value
    return sanitized

def safe_error_details(exc: BaseException) -> dict:
    details = {"errorType": type(exc).__name__}
    errors_method = getattr(exc, "errors", None)
    if callable(errors_method):
        try:
            errors = errors_method(include_input=False, include_context=False, include_url=False)
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
            "message": record.getMessage(),
            "tenant": self.tenant,
        }

        ctx = _log_context.get()
        sanitized_ctx = _sanitize_log_fields(dict(ctx), source="context")
        log_record["stage"] = sanitized_ctx.get("stage", self.stage)
        for k in ("documentId", "correlationId", "traceId"):
            if k in sanitized_ctx:
                log_record[k] = sanitized_ctx[k]

        _internal_keys = frozenset({
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "module", "msecs",
            "message", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
            "taskName",
        })
        extras = {k: v for k, v in record.__dict__.items() if k not in _internal_keys}

        event_fields = extras.pop("_scanalyze_event_fields", None)
        if isinstance(event_fields, dict):
            safe_event_fields = _sanitize_log_fields(event_fields, source="event")
            for k, v in safe_event_fields.items():
                if k not in log_record:
                    log_record[k] = v

        sanitized_extras = _sanitize_log_fields(extras, source="extra")
        if record.exc_info and record.exc_info[0] is not None:
            sanitized_extras.setdefault("errorType", record.exc_info[0].__name__)

        for k, v in sanitized_extras.items():
            if k not in log_record:
                log_record[k] = v

        return json.dumps(log_record, allow_nan=False)

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
    logger = logging.getLogger('ocr_worker.structured')
    safe_kwargs = _sanitize_log_fields(kwargs, source="event")
    logger.info(event_name, extra={"event": event_name, "_scanalyze_event_fields": safe_kwargs})
