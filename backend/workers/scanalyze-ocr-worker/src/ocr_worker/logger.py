import logging
import os
import json
import contextvars
import re
import math
from datetime import datetime, timezone

from .environment_contract import (
    project_log_environment,
    project_customer_id,
    project_deployment_id
)

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
    "document_route": frozenset({"platform", "default", "bank", "personal", "gov"}),
    "next_stage": frozenset({"classify", "bank-extract", "personal-extract", "gov-extract"}),
    "reason": frozenset({"missing_message_id", "test_reason", "textract_failure", "dynamo_failure", "sqs_failure"}),
}

def _val_enum(field: str):
    def validator(value):
        if not isinstance(value, str): return None
        cleaned = _CONTROL_CHAR_RE.sub('', value)
        return cleaned if cleaned in _ENUMS[field] else None
    return validator

def _val_document_id(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", cleaned) else None

def _val_uuid(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if re.fullmatch(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", cleaned, re.IGNORECASE) else None

def _val_job_id(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if re.fullmatch(r"^[A-Za-z0-9_-]{1,64}$", cleaned) else None

def _val_queue(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if re.fullmatch(r"^[A-Za-z0-9_-]{1,64}$", cleaned) else None

def _val_error_type(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if re.fullmatch(r"^[A-Za-z0-9]{1,128}$", cleaned) else None

def _val_event(value):
    if not isinstance(value, str): return None
    cleaned = _CONTROL_CHAR_RE.sub('', value)
    return cleaned if len(cleaned) <= 64 else None

def _val_counter(value):
    if type(value) is bool: return None
    if type(value) is float: return None
    if isinstance(value, int):
        return value if value >= 0 else None
    return None

FIELD_VALIDATORS = {
    "status": _val_enum("status"),
    "state": _val_enum("state"),
    "stage": _val_enum("stage"),
    "document_route": _val_enum("document_route"),
    "next_stage": _val_enum("next_stage"),
    "reason": _val_enum("reason"),
    "documentId": _val_document_id,
    "message_id": _val_uuid,
    "messageId": _val_uuid,
    "downstream_message_id": _val_uuid,
    "jobId": _val_job_id,
    "textractJobId": _val_job_id,
    "queue": _val_queue,
    "queue_name": _val_queue,
    "errorType": _val_error_type,
    "event": _val_event,
    "errorCount": _val_counter,
    "parameterCount": _val_counter,
    "attempt": _val_counter,
    "receiveCount": _val_counter,
    "receive_count": _val_counter,
    "delay": _val_counter,
    "signal": _val_counter,
    "line": _val_counter,
    "column": _val_counter,
}

def _sanitize_scalar(value: object, field: str = None) -> object:
    if value is None:
        return None
    validator = FIELD_VALIDATORS.get(field)
    if validator:
        return validator(value)

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
        self.env = project_log_environment(os.environ.get('SCANALYZE_ENV'))
        self.deployment_id = project_deployment_id(os.environ.get('SCANALYZE_DEPLOYMENT_ID'))
        self.customer_id = project_customer_id(os.environ.get('SCANALYZE_DEPLOYMENT_CUSTOMER_ID'))

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

        msg = str(record.getMessage())
        if len(msg) > 1024:
            msg = msg[:1024]

        merged["timestamp"] = datetime.fromtimestamp(record.created, timezone.utc).isoformat()
        merged["level"] = level
        merged["env"] = env
        merged["deploymentId"] = self.deployment_id
        merged["customerId"] = self.customer_id
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
