"""Permanent CI guard for OCR worker import layouts and log-redaction invariants.

Proves that the canonical ``get_logger`` owner, source-layout imports, and
container-layout imports all resolve correctly.  Also validates that the
structured JSON formatter redacts sensitive fields and preserves correlation IDs.

Linear: GUG-105
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SERVICE_DIR = REPO_ROOT / "backend" / "workers" / "scanalyze-ocr-worker"
SRC_DIR = SERVICE_DIR / "src"
DOCKERFILE = SERVICE_DIR / "Dockerfile"


# ---------------------------------------------------------------------------
# Import-layout guards
# ---------------------------------------------------------------------------


def _run_python(snippet: str, pythonpath: str) -> subprocess.CompletedProcess[str]:
    """Run a Python snippet in a subprocess with controlled PYTHONPATH."""
    import os

    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath
    env["SCANALYZE_ENV"] = "test"
    env["SCANALYZE_TENANT"] = "platform"
    env["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    env["SCANALYZE_DEPLOYMENT_ID"] = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    env["SCANALYZE_PARAM_ROOT"] = "/scanalyze/test/tenants"
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["AWS_REGION"] = "us-east-1"
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(snippet)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_source_layout_import():
    """Canonical source-layout import succeeds (PYTHONPATH=<service>/src)."""
    result = _run_python(
        """\
        from ocr_worker.logger import get_logger
        from ocr_worker.usage import record_usage_metering_with_idempotency
        assert callable(get_logger)
        assert callable(record_usage_metering_with_idempotency)
        print("OCR_SOURCE_IMPORT_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "OCR_SOURCE_IMPORT_OK" in result.stdout


def test_container_layout_import():
    """Docker-layout import succeeds (PYTHONPATH=<service>, from src.ocr_worker…)."""
    result = _run_python(
        """\
        from src.ocr_worker.logger import get_logger
        import src.ocr_worker.usage
        import src.ocr_worker.main
        assert callable(get_logger)
        print("OCR_CONTAINER_LAYOUT_IMPORT_OK")
        """,
        pythonpath=str(SERVICE_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "OCR_CONTAINER_LAYOUT_IMPORT_OK" in result.stdout


# ---------------------------------------------------------------------------
# Canonical-owner uniqueness guard
# ---------------------------------------------------------------------------


def test_get_logger_has_one_canonical_owner():
    """Exactly one production definition of ``get_logger`` exists."""
    logger_py = SRC_DIR / "ocr_worker" / "logger.py"
    source = logger_py.read_text(encoding="utf-8")
    assert source.count("def get_logger(") == 1, "get_logger must be defined exactly once"

    # No duplicate logging utility module
    for path in (SRC_DIR / "ocr_worker").rglob("*.py"):
        if path.name in ("logger.py", "__init__.py"):
            continue
        content = path.read_text(encoding="utf-8")
        assert "def get_logger(" not in content, (
            f"Duplicate get_logger definition found in {path.relative_to(REPO_ROOT)}"
        )


def test_usage_imports_canonical_logger():
    """usage.py imports get_logger from the canonical sibling module."""
    usage_py = SRC_DIR / "ocr_worker" / "usage.py"
    source = usage_py.read_text(encoding="utf-8")
    assert "from .logger import get_logger" in source


# ---------------------------------------------------------------------------
# Dockerfile contract guard
# ---------------------------------------------------------------------------


def test_dockerfile_entrypoint_references_src_module():
    """The ENTRYPOINT runs through ``src.ocr_worker.main``."""
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "src.ocr_worker.main" in content, (
        "Dockerfile ENTRYPOINT must reference the src.ocr_worker.main module"
    )


def test_dockerfile_copies_src_into_app():
    """The Dockerfile copies src/ into the container /app root."""
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY" in content and "src/" in content, (
        "Dockerfile must COPY src/ into the container"
    )


# ---------------------------------------------------------------------------
# Log-redaction guards
# ---------------------------------------------------------------------------


def test_log_redaction_filters_sensitive_fields():
    """Structured formatter filters OCR content, PII and raw-body sentinels."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, bind_context, clear_context

        setup_logging()
        bind_context(correlationId="corr-test-gug105")

        logger = logging.getLogger("test.redaction")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Attempt to inject sensitive fields through extra
        logger.info(
            "redaction_test",
            extra={
                "event": "redaction_smoke",
                "ocrText": "SYNTHETIC_OCR_CONTENT_SENTINEL",
                "personIdentifiers": "SYNTHETIC_PERSON_IDENTIFIER_SENTINEL",
                "rawBody": "SYNTHETIC_RAW_BODY_SENTINEL",
                "documentId": "doc-safe-123",
            },
        )

        clear_context()
        output = stream.getvalue().strip()
        for line in output.splitlines():
            record = json.loads(line)
            serialized = json.dumps(record)
            assert "SYNTHETIC_OCR_CONTENT_SENTINEL" not in serialized
            assert "SYNTHETIC_PERSON_IDENTIFIER_SENTINEL" not in serialized
            assert "SYNTHETIC_RAW_BODY_SENTINEL" not in serialized
            assert record.get("correlationId") == "corr-test-gug105"
            assert record.get("event") == "redaction_smoke"
        print("LOG_REDACTION_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "LOG_REDACTION_OK" in result.stdout


def test_log_exception_redacts_message():
    """Exception logging emits type but not the raw exception message."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging

        setup_logging()
        logger = logging.getLogger("test.exception")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.ERROR)

        try:
            raise ValueError("SYNTHETIC_SECRET_SENTINEL in exception")
        except ValueError:
            logger.error("handled error", exc_info=True)

        output = stream.getvalue().strip()
        for line in output.splitlines():
            record = json.loads(line)
            serialized = json.dumps(record)
            assert "SYNTHETIC_SECRET_SENTINEL" not in serialized
            assert record.get("errorType") == "ValueError"
            # No traceback in JSON output
            assert "Traceback" not in serialized
        print("LOG_EXCEPTION_REDACTION_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "LOG_EXCEPTION_REDACTION_OK" in result.stdout


def test_log_output_is_valid_json():
    """Every log line produced by the structured formatter is valid JSON."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, bind_context, clear_context

        setup_logging()
        bind_context(correlationId="corr-json-check")

        logger = logging.getLogger("test.json")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        logger.info("line one")
        logger.warning("line two", extra={"event": "check"})
        logger.debug("line three")

        clear_context()
        output = stream.getvalue().strip()
        lines = output.splitlines()
        assert len(lines) >= 2  # debug may be filtered by level
        for line in lines:
            parsed = json.loads(line)
            assert "timestamp" in parsed
            assert "level" in parsed
        print("LOG_JSON_VALID")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "LOG_JSON_VALID" in result.stdout
