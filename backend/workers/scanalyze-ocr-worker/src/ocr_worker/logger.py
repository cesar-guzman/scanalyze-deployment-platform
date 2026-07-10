import logging
import os
import json
import contextvars
import re
from datetime import datetime, timezone

_log_context = contextvars.ContextVar('scanalyze_log_context', default={})


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
    ctx = _log_context.get().copy()
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
    for k, v in kwargs.items():
        nk = mapping.get(k, k)
        if v is not None:
            ctx[nk] = v
    _log_context.set(ctx)

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
        
        ctx = _log_context.get()
        for k, v in ctx.items():
            log_record[k] = v
            
        if record.exc_info:
            # Tracebacks include exception messages, which can contain document data.
            log_record["errorType"] = record.exc_info[0].__name__
            
        if hasattr(record, 'event'):
            log_record["event"] = record.event
            
        for k, v in record.__dict__.items():
            if k not in ["args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName", "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name", "pathname", "process", "processName", "relativeCreated", "stack_info", "thread", "threadName", "event"]:
                kl = k.lower()
                if "text" not in kl and "ocr" not in kl and "person" not in kl and "identifier" not in kl:
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
    logger = logging.getLogger('ocr_worker.structured')
    
    safe_kwargs = {k: v for k, v in kwargs.items() if "text" not in k.lower() and "ocr" not in k.lower() and "person" not in k.lower() and "identifiers" not in k.lower()}
    
    logger.info(event_name, extra={"event": event_name, **safe_kwargs})
