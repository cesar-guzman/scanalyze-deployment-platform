import logging
import os
import json
import contextvars
import re
import math
from datetime import datetime, timezone

_log_context = contextvars.ContextVar('scanalyze_log_context', default={})

_SOURCE_PERMISSIONS = {
    "context": frozenset({"correlationId", "traceId", "documentId", "stage"}),
    "event": frozenset({
        "signal", "queue", "queue_name", "message_id", "receive_count",
        "messageId", "receiveCount", "jobId", "textractJobId",
        "document_route", "downstream_message_id", "delay", "attempt",
        "status", "state", "next_stage", "reason", "errorType", "errorCount",
        "invalidFields", "line", "column"
    }),
    "extra": frozenset({"event", "errorType", "parameterCount", "line", "column"})
}

_EVENT_TOKEN = object()

class _ScanalyzeEventFields(dict):
    """Private event envelope to prevent accidental Extra overwrite."""
    def __init__(self, token: object, *args, **kwargs):
        if token is not _EVENT_TOKEN:
            raise ValueError("Private constructor")
        super().__init__(*args, **kwargs)
        self._token = token

_MAX_VALUE_LENGTH = 1024
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

_ENUMS = {
    "status": frozenset({"SUBMITTED", "ENQUEUED", "OCR", "BANK_EXTRACTED", "CLASSIFY_COMPLETED", "SUCCEEDED", "FAILED", "IN_PROGRESS", "PARTIAL_SUCCESS", "COMPLETED", "HANDOFF_ENQUEUED"}),
    "state": frozenset({"OCR_COMPLETED", "HANDOFF_ENQUEUED", "FAILED", "SUBMITTED", "ENQUEUED", "IN_PROGRESS"}),
    "stage": frozenset({"scanalyze-ocr-worker", "ocr_ingest", "ocr"}),
    "document_route": frozenset({"standard", "default", "bank", "personal", "gov", "fast", "express"}),
    "next_stage": frozenset({"classify", "postprocess", "bank", "personal", "gov"}),
    "reason": frozenset({"missing_message_id", "test_reason", "textract_failure", "dynamo_failure", "sqs_failure"}),
}

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")
_SAFE_ERR_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")

def _sanitize_scalar(value: object, field: str = None) -> object:
    if value is None:
        return None
    counters = frozenset({"errorCount", "parameterCount", "attempt", "receiveCount", "receive_count", "delay", "signal", "line", "column"})
    if type(value) is bool:
        return None if field in counters else value
    if isinstance(value, (int, float)):
        if type(value) is float:
            return None if field in counters or not math.isfinite(value) else value
        if type(value) is not bool and isinstance(value, int):
            return None if field in counters and value < 0 else value
        return value
    if isinstance(value, str):
        cleaned = _CONTROL_CHAR_RE.sub('', value)
        
        if field in _ENUMS:
            return cleaned if cleaned in _ENUMS[field] else None
            
        if field == "errorType":
            return cleaned if _SAFE_ERR_RE.fullmatch(cleaned) else None
            
        id_fields = {"message_id", "messageId", "downstream_message_id", "jobId", "textractJobId", "queue", "queue_name", "documentId"}
        if field in id_fields:
            return cleaned if _SAFE_ID_RE.fullmatch(cleaned) else None
            
        if field == "event":
            return cleaned if len(cleaned) <= 64 else None
            
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
    if field == "correlationId":
        if not isinstance(value, str):
            return None
        if re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value, flags=re.IGNORECASE):
            return value
        if re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", value, flags=re.IGNORECASE):
            return value
        return None
    if field == "traceId":
        if not isinstance(value, str):
            return None
        if re.fullmatch(r"[a-f0-9]{32}", value, flags=re.IGNORECASE) and value != "0"*32:
            return value
        if re.fullmatch(r"1-[a-f0-9]{8}-[a-f0-9]{24}", value, flags=re.IGNORECASE):
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

        # 3. Event Overrides Extra
        if isinstance(event_fields, _ScanalyzeEventFields) and getattr(event_fields, "_token", None) is _EVENT_TOKEN:
            sanitized_event = _sanitize_log_fields(event_fields, source="event")
            for k, v in sanitized_event.items():
                if k == "event":
                    val = str(v)
                    if re.fullmatch(r"[a-z0-9_]{1,64}", val):
                        merged["event"] = val
                elif k == "errorType":
                    val = str(v)
                    if re.fullmatch(r"[A-Za-z0-9]{1,128}", val):
                        merged["errorType"] = val
                elif k not in ("tenant", "stage", "documentId", "correlationId", "traceId"):
                    merged[k] = v

        if record.exc_info and record.exc_info[0] is not None:
            err_type = record.exc_info[0].__name__
            if re.fullmatch(r"[A-Za-z0-9]{1,128}", err_type):
                merged["errorType"] = err_type

        # 2. Context Overrides Event/Extra
        ctx = _log_context.get()
        sanitized_ctx = _sanitize_log_fields(dict(ctx), source="context")
        
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

        # 1. Core Overrides Everything
        tenant = self.tenant
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", str(tenant)):
            tenant = "unknown"
        merged["tenant"] = tenant

        level = record.levelname.lower()
        if level not in ("info", "warn", "error", "debug", "fatal", "warning", "critical"):
            level = "warn" if level == "warning" else "info"
                
        env = self.env
        if env not in ("local", "dev", "test", "staging", "prod", "ci"):
            env = "unknown"
            
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
    envelope = _ScanalyzeEventFields(_EVENT_TOKEN, **kwargs)
    logger.info(event_name, extra={"event": event_name, "_scanalyze_event_fields": envelope})
