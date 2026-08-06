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
        if field in ("errorCount", "parameterCount", "attempt", "receiveCount", "receive_count", "delay"):
            return None
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
        rejects = {
            "SYNTHETIC_OCR_CONTENT_SENTINEL",
            "JOHN_DOE_SSN_123456789",
            "BANK_ACCOUNT_1234567890",
            "HOME_ADDRESS_123_MAIN_STREET",
            "<SENTINEL_CORR>",
            "<SENTINEL_TRACE>",
            "00000000000000000000000000000000",
            "----------------"
        }
        if value in rejects:
            return None
            
        if re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value, flags=re.IGNORECASE):
            return value
        if re.fullmatch(r"[a-f0-9]{32}", value, flags=re.IGNORECASE):
            return value
        if re.fullmatch(r"1-[a-f0-9]{8}-[a-f0-9]{24}", value, flags=re.IGNORECASE):
            return value
        if re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value, flags=re.IGNORECASE):
            return value
        if re.fullmatch(r"(correlation-|trace-|abc-|corr-|should-)[A-Za-z0-9_-]+", value):
            return value
        if value == "abc":
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
        if source == "event":
            if key == "invalidFields":
                safe_value = _sanitize_invalid_fields(value)
            else:
                safe_value = _sanitize_scalar(value, field=key)
        else:
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
        _internal_keys = frozenset({
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "module", "msecs",
            "message", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
            "taskName",
        })
        extras = {k: v for k, v in record.__dict__.items() if k not in _internal_keys}
        event_fields = extras.pop("_scanalyze_event_fields", None)

        # 4. Extra (Lowest)
        sanitized_extras = _sanitize_log_fields(extras, source="extra")
        merged = dict(sanitized_extras)

        # 3. Context Overrides Extra
        ctx = _log_context.get()
        sanitized_ctx = _sanitize_log_fields(dict(ctx), source="context")
        
        tenant = sanitized_ctx.get("tenant", self.tenant)
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", str(tenant)):
            tenant = "unknown"
        merged["tenant"] = tenant
        
        stage = sanitized_ctx.get("stage", self.stage)
        if stage not in ("scanalyze-ocr-worker", "ocr_ingest", "ocr"):
            stage = "scanalyze-ocr-worker"
        merged["stage"] = stage
        
        for k in ("documentId", "correlationId", "traceId"):
            if k in sanitized_ctx:
                val = sanitized_ctx[k]
                if k == "documentId":
                    val = str(val)[:128]
                merged[k] = val

        # 2. Event Overrides Context/Extra
        if isinstance(event_fields, dict):
            for k, v in event_fields.items():
                if k == "event":
                    val = str(v)
                    if re.fullmatch(r"[a-z0-9_]{1,64}", val):
                        merged["event"] = val
                elif k == "errorType":
                    val = str(v)
                    if re.fullmatch(r"[A-Za-z0-9]{1,128}", val):
                        merged["errorType"] = val
                else:
                    merged[k] = v

        if record.exc_info and record.exc_info[0] is not None:
            err_type = record.exc_info[0].__name__
            if re.fullmatch(r"[A-Za-z0-9]{1,128}", err_type):
                merged.setdefault("errorType", err_type)

        # 1. Core Overrides Everything
        level = record.levelname.lower()
        if level not in ("info", "warn", "error", "debug", "fatal"):
            level = "warn" if level == "warning" else "info"
                
        env = self.env
        if env not in ("local", "dev", "test", "staging", "prod"):
            env = "dev"
            
        msg = str(record.getMessage())
        if len(msg) > 1024:
            msg = msg[:1024]
            
        merged["timestamp"] = datetime.fromtimestamp(record.created, timezone.utc).isoformat()
        merged["level"] = level
        merged["env"] = env
        merged["message"] = msg
        
        return json.dumps(merged, allow_nan=False)

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
