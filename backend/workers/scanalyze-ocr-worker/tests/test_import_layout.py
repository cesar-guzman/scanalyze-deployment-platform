"""Permanent CI guard for OCR worker import layouts, log-redaction invariants,
and the centralised fail-closed metadata sanitiser.

Proves that:
1. Canonical ``get_logger`` owner, source-layout imports, and container-layout
   imports all resolve correctly.
2. The centralised sanitiser drops unknown fields, nested structures, custom
   objects, oversized strings, and control characters.
3. All three entry paths (bind_context, log_event, LogRecord extra) enforce the
   same allowlist through the complete serialised JSON output.
4. The Dockerfile contract is valid.
5. Log-format message channels do not leak payload variables.

Linear: GUG-105
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SERVICE_DIR = REPO_ROOT / "backend" / "workers" / "scanalyze-ocr-worker"
SRC_DIR = SERVICE_DIR / "src"
DOCKERFILE = SERVICE_DIR / "Dockerfile"

_AWS_ENVIRONMENT_KEYS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
}

_HERMETIC_IMPORT_BOOTSTRAP = """\
import boto3
import socket

class _FakeAWSService:
    def __getattr__(self, name):
        raise AssertionError(f"AWS service call attempted during import: {name}")

class _FakeBotoSession:
    def __init__(self, *args, **kwargs):
        pass

    def client(self, *args, **kwargs):
        return _FakeAWSService()

    def resource(self, *args, **kwargs):
        return _FakeAWSService()

def _fake_boto_client(*args, **kwargs):
    return _FakeAWSService()

def _fake_boto_resource(*args, **kwargs):
    return _FakeAWSService()

class _BlockedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        raise AssertionError("Network access attempted during hermetic import")

    def connect_ex(self, *args, **kwargs):
        raise AssertionError("Network access attempted during hermetic import")

def _blocked_create_connection(*args, **kwargs):
    raise AssertionError("Network access attempted during hermetic import")

boto3.client = _fake_boto_client
boto3.resource = _fake_boto_resource
boto3.Session = _FakeBotoSession
boto3._scanalyze_hermetic_fake = True
socket.socket = _BlockedSocket
socket.create_connection = _blocked_create_connection
"""


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------


def _run_python(snippet: str, pythonpath: str) -> subprocess.CompletedProcess[str]:
    """Run a Python snippet with no ambient AWS identity or network access."""
    env = os.environ.copy()
    for key in _AWS_ENVIRONMENT_KEYS:
        env.pop(key, None)

    env["PYTHONPATH"] = pythonpath
    env["SCANALYZE_ENV"] = "test"
    env["SCANALYZE_TENANT"] = "platform"
    env["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    env["SCANALYZE_DEPLOYMENT_ID"] = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    env["SCANALYZE_PARAM_ROOT"] = "/scanalyze/test/tenants"
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["AWS_REGION"] = "us-east-1"
    env["AWS_DEFAULT_REGION"] = "us-east-1"
    env["AWS_CONFIG_FILE"] = os.devnull
    env["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    env["BOTO_CONFIG"] = os.devnull

    isolated_snippet = _HERMETIC_IMPORT_BOOTSTRAP + "\n" + textwrap.dedent(snippet)
    return subprocess.run(
        [sys.executable, "-c", isolated_snippet],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )


# ===========================================================================
# 1. Import-layout guards
# ===========================================================================


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
        import boto3
        import socket
        assert boto3._scanalyze_hermetic_fake is True
        assert socket.socket.__name__ == "_BlockedSocket"
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


def test_import_runner_removes_ambient_aws_identity(monkeypatch):
    """Import guards must not inherit developer or CI AWS identity settings."""
    for key in _AWS_ENVIRONMENT_KEYS:
        monkeypatch.setenv(key, "must-not-reach-subprocess")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/must/not/be/read")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/must/not/be/read")

    result = _run_python(
        f"""\
        import os
        forbidden = {sorted(_AWS_ENVIRONMENT_KEYS)!r}
        assert not set(forbidden).intersection(os.environ)
        assert os.environ["AWS_CONFIG_FILE"] == os.devnull
        assert os.environ["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
        assert os.environ["BOTO_CONFIG"] == os.devnull
        print("OCR_IMPORT_ENV_HERMETIC")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "OCR_IMPORT_ENV_HERMETIC" in result.stdout


# ===========================================================================
# 2. Canonical-owner uniqueness guard
# ===========================================================================


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


# ===========================================================================
# 3. Dockerfile contract guard
# ===========================================================================


def _effective_dockerfile_instructions(content: str) -> list[str]:
    """Return logical Dockerfile instructions, excluding blank/comment lines."""
    instructions: list[str] = []
    continued_parts: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        is_continued = line.endswith("\\")
        continued_parts.append(line[:-1].rstrip() if is_continued else line)
        if not is_continued:
            instructions.append(" ".join(continued_parts))
            continued_parts.clear()

    if continued_parts:
        raise ValueError("Dockerfile ends with an incomplete continued instruction")
    return instructions


def _assert_exact_worker_entrypoint(instructions: list[str]) -> None:
    expected = 'ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]'
    entrypoints = [
        instruction
        for instruction in instructions
        if instruction.split(maxsplit=1)[0].upper() == "ENTRYPOINT"
    ]
    assert entrypoints == [expected], (
        "Dockerfile must contain exactly one effective ENTRYPOINT equal to "
        f"{expected}; found {entrypoints}"
    )


def _assert_hermetic_dependency_install(instructions: list[str]) -> None:
    lock_copy = "COPY requirements.lock ."
    wheelhouse_copy = "COPY .wheelhouse/ /wheelhouse/"
    lock_copies = [instruction for instruction in instructions if instruction == lock_copy]
    copies = [instruction for instruction in instructions if instruction == wheelhouse_copy]
    assert lock_copies == [lock_copy], (
        "Dockerfile must copy exactly one reviewed requirements.lock"
    )
    assert copies == [wheelhouse_copy], (
        "Dockerfile must copy exactly one generated .wheelhouse into /wheelhouse"
    )

    installs = [
        instruction
        for instruction in instructions
        if instruction.upper().startswith("RUN ")
        and "pip install" in instruction
        and "requirements.lock" in instruction
    ]
    assert len(installs) == 1, (
        "Dockerfile must contain exactly one locked requirements install instruction"
    )
    install = installs[0]
    assert "--no-index" in install
    assert "--require-hashes" in install
    assert (
        "--find-links=/wheelhouse" in install
        or "--find-links /wheelhouse" in install
    )
    assert instructions.index(lock_copy) < instructions.index(install)
    assert instructions.index(wheelhouse_copy) < instructions.index(install)

    forbidden_network_commands = ("apt-get", "apk ", "dnf ", "yum ", "curl ", "wget ")
    run_instructions = [
        instruction
        for instruction in instructions
        if instruction.upper().startswith("RUN ")
    ]
    assert not any(
        command in instruction
        for instruction in run_instructions
        for command in forbidden_network_commands
    ), "Hermetic Dockerfile RUN instructions must not invoke network package tools"


def test_dockerfile_entrypoint_references_src_module():
    """The effective ENTRYPOINT is the exact supported module invocation."""
    instructions = _effective_dockerfile_instructions(
        DOCKERFILE.read_text(encoding="utf-8")
    )
    _assert_exact_worker_entrypoint(instructions)


def test_dockerfile_entrypoint_rejects_later_override():
    """A second ENTRYPOINT cannot override the validated worker command."""
    instructions = _effective_dockerfile_instructions(
        """
        ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]
        ENTRYPOINT ["python", "src/ocr_worker/main.py"]
        """
    )
    with pytest.raises(AssertionError, match="exactly one effective ENTRYPOINT"):
        _assert_exact_worker_entrypoint(instructions)


def test_dockerfile_copies_src_into_app():
    """The effective COPY preserves the runtime layout and file ownership."""
    instructions = _effective_dockerfile_instructions(
        DOCKERFILE.read_text(encoding="utf-8")
    )
    assert "COPY --chown=app:app src/ ./src/" in instructions, (
        "Dockerfile must use the exact owned src/ copy contract"
    )


def test_dockerfile_installs_requirements_from_generated_wheelhouse_only():
    """The OCR image dependency layer is consumable with Docker network disabled."""
    instructions = _effective_dockerfile_instructions(
        DOCKERFILE.read_text(encoding="utf-8")
    )
    _assert_hermetic_dependency_install(instructions)


def test_hermetic_dependency_guard_rejects_online_or_late_install():
    instructions = _effective_dockerfile_instructions(
        """
        RUN pip install -r requirements.lock
        COPY requirements.lock .
        COPY .wheelhouse/ /wheelhouse/
        """
    )
    with pytest.raises(AssertionError):
        _assert_hermetic_dependency_install(instructions)


def test_dockerfile_parser_ignores_commented_contracts():
    """Commented examples cannot make a broken Dockerfile contract look valid."""
    instructions = _effective_dockerfile_instructions(
        """
        # COPY --chown=app:app src/ ./src/
        COPY src/ /wrong-layout/
        # COPY requirements.lock .
        # COPY .wheelhouse/ /wheelhouse/
        # ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]
        ENTRYPOINT ["python", "src/ocr_worker/main.py"]
        """
    )
    assert "COPY --chown=app:app src/ ./src/" not in instructions
    assert "COPY requirements.lock ." not in instructions
    assert "COPY .wheelhouse/ /wheelhouse/" not in instructions
    assert 'ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]' not in instructions


# ===========================================================================
# 4. Centralised sanitiser unit tests (in-process)
# ===========================================================================


class TestSanitizeLogFields:
    """Direct unit tests for _sanitize_log_fields."""

    @pytest.fixture(autouse=True)
    def _patch_path(self):
        """Ensure SRC_DIR is importable."""
        already = str(SRC_DIR) in sys.path
        if not already:
            sys.path.insert(0, str(SRC_DIR))
        yield
        if not already:
            sys.path.remove(str(SRC_DIR))

    def test_allowed_scalars_pass_through(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"correlationId": "550e8400-e29b-41d4-a716-446655440000", "documentId": "doc-1", "errorType": "ValueError"},
            source="context",
        )
        assert result == {"correlationId": "550e8400-e29b-41d4-a716-446655440000", "documentId": "doc-1"}

    def test_unknown_fields_are_dropped(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"rawBody": "SENTINEL", "payload": "SENTINEL", "content": "SENTINEL"},
            source="event",
        )
        assert result == {}

    def test_nested_dicts_are_dropped(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"documentId": {"rawBody": "SENTINEL"}},
            source="extra",
        )
        assert result == {}

    def test_nested_lists_are_dropped_except_invalidFields(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"documentId": ["a", "b"], "invalidFields": ["field1", "field2"]},
            source="event",
        )
        assert "documentId" not in result
        assert result["invalidFields"] == ["field1", "field2"]

    def test_custom_objects_are_dropped(self):
        from ocr_worker.logger import _sanitize_log_fields

        class Secret:
            def __str__(self): return "LEAKED"
            def __repr__(self): return "LEAKED"

        result = _sanitize_log_fields({"documentId": Secret()}, source="extra")
        assert result == {}

    def test_oversized_ids_are_dropped(self):
        from ocr_worker.logger import _sanitize_log_fields, _MAX_VALUE_LENGTH
        long_val = "x" * 300
        result = _sanitize_log_fields({"queue": long_val}, source="event")
        assert "queue" not in result

    def test_control_characters_fail_closed(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields({"documentId": "doc\x00\x01\x02-123", "correlationId": "550e8400-e29b-41d4-a716-446655440000\n"}, source="context")
        assert "documentId" not in result
        assert "correlationId" not in result

    def test_leading_trailing_whitespace_fail_closed(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields({"documentId": " doc-123 ", "correlationId": "\t550e8400-e29b-41d4-a716-446655440000"}, source="context")
        assert "documentId" not in result
        assert "correlationId" not in result

    def test_invalidFields_bounded_to_20(self):
        from ocr_worker.logger import _sanitize_log_fields
        fields = [f"field_{i}" for i in range(30)]
        result = _sanitize_log_fields({"invalidFields": fields}, source="event")
        assert len(result["invalidFields"]) == 20

    def test_invalidFields_rejects_unsafe_patterns(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"invalidFields": ["valid_field", "has spaces", "a" * 100, "ok.<field>"]},
            source="event",
        )
        # "has spaces" fails regex, "a"*100 exceeds 64 chars
        # "ok.<field>" passes (safe_error_details emits this pattern)
        assert result["invalidFields"] == ["valid_field", "ok.<field>"]

    def test_none_values_are_dropped(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields({"documentId": None, "correlationId": "550e8400-e29b-41d4-a716-446655440000"}, source="context")
        assert "documentId" not in result
        assert result["correlationId"] == "550e8400-e29b-41d4-a716-446655440000"

    def test_numeric_values_pass_through(self):
        from ocr_worker.logger import _sanitize_log_fields
        result = _sanitize_log_fields(
            {"delay": 30, "receive_count": 3, "parameterCount": 15},
            source="extra",
        )
        assert result == {"parameterCount": 15}
        
        result_event = _sanitize_log_fields(
            {"delay": 30, "receive_count": 3, "parameterCount": 15},
            source="event",
        )
        assert result_event == {"delay": 30, "receive_count": 3}

    def test_boolean_values_pass_through_for_non_counters(self):
        from ocr_worker.logger import _sanitize_log_fields
        # booleans should be rejected for counters like 'signal'
        result = _sanitize_log_fields({"signal": True}, source="event")
        assert result == {}


# ===========================================================================
# 5. End-to-end redaction via bind_context (subprocess)
# ===========================================================================


class TestBindContextRedaction:
    """Prove that bind_context + JSONFormatter drops sensitive data."""

    def _assert_sentinel_absent(self, snippet: str, sentinel: str):
        result = _run_python(snippet, pythonpath=str(SRC_DIR))
        assert result.returncode == 0, result.stderr
        for line in result.stdout.strip().splitlines():
            if line.startswith("{"):
                assert sentinel not in line, f"Sentinel '{sentinel}' leaked in: {line}"

    def test_context_rawBody_dropped(self):
        self._assert_sentinel_absent(
            """\
            import json, logging, io
            from ocr_worker.logger import setup_logging, bind_context, clear_context

            setup_logging()
            bind_context(rawBody="SENTINEL_RAW_BODY")
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("check")
            clear_context()
            print(stream.getvalue())
            """,
            "SENTINEL_RAW_BODY",
        )

    def test_context_payload_dropped(self):
        self._assert_sentinel_absent(
            """\
            import json, logging, io
            from ocr_worker.logger import setup_logging, bind_context, clear_context

            setup_logging()
            bind_context(payload="SENTINEL_PAYLOAD")
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("check")
            clear_context()
            print(stream.getvalue())
            """,
            "SENTINEL_PAYLOAD",
        )

    def test_context_nested_dict_dropped(self):
        self._assert_sentinel_absent(
            """\
            import json, logging, io
            from ocr_worker.logger import setup_logging, bind_context, clear_context

            setup_logging()
            bind_context(metadata={"rawBody": "SENTINEL_NESTED_BODY"})
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("check")
            clear_context()
            print(stream.getvalue())
            """,
            "SENTINEL_NESTED_BODY",
        )


# ===========================================================================
# 6. End-to-end redaction via LogRecord extra (subprocess)
# ===========================================================================


class TestLogRecordExtraRedaction:
    """Prove that extra={} on logger calls is fail-closed."""

    def _assert_sentinel_absent(self, snippet: str, sentinel: str):
        result = _run_python(snippet, pythonpath=str(SRC_DIR))
        assert result.returncode == 0, result.stderr
        for line in result.stdout.strip().splitlines():
            if line.startswith("{"):
                assert sentinel not in line, f"Sentinel '{sentinel}' leaked in: {line}"

    def test_extra_rawBody_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging

            setup_logging()
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("test", extra={"rawBody": "SENTINEL_EXTRA_RAW"})
            print(stream.getvalue())
            """,
            "SENTINEL_EXTRA_RAW",
        )

    def test_extra_payload_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging

            setup_logging()
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("test", extra={"payload": "SENTINEL_EXTRA_PAYLOAD"})
            print(stream.getvalue())
            """,
            "SENTINEL_EXTRA_PAYLOAD",
        )

    def test_extra_nested_dict_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging

            setup_logging()
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("test", extra={"metadata": {"rawBody": "SENTINEL_NESTED_EXTRA"}})
            print(stream.getvalue())
            """,
            "SENTINEL_NESTED_EXTRA",
        )

    def test_extra_content_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging

            setup_logging()
            logger = logging.getLogger("test")
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.info("test", extra={"content": "SENTINEL_CONTENT"})
            print(stream.getvalue())
            """,
            "SENTINEL_CONTENT",
        )


# ===========================================================================
# 7. End-to-end redaction via log_event (subprocess)
# ===========================================================================


class TestLogEventRedaction:
    """Prove that log_event() kwargs are fail-closed."""

    def _assert_sentinel_absent(self, snippet: str, sentinel: str):
        result = _run_python(snippet, pythonpath=str(SRC_DIR))
        assert result.returncode == 0, result.stderr
        for line in result.stdout.strip().splitlines():
            if line.startswith("{"):
                assert sentinel not in line, f"Sentinel '{sentinel}' leaked in: {line}"

    def test_log_event_rawBody_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging, log_event

            setup_logging()
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logging.getLogger("ocr_worker.structured").addHandler(handler)
            log_event("test_event", rawBody="SENTINEL_EVENT_RAW")
            print(stream.getvalue())
            """,
            "SENTINEL_EVENT_RAW",
        )

    def test_log_event_payload_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging, log_event

            setup_logging()
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logging.getLogger("ocr_worker.structured").addHandler(handler)
            log_event("test_event", payload="SENTINEL_EVENT_PAYLOAD")
            print(stream.getvalue())
            """,
            "SENTINEL_EVENT_PAYLOAD",
        )

    def test_log_event_nested_dict_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging, log_event

            setup_logging()
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logging.getLogger("ocr_worker.structured").addHandler(handler)
            log_event("test_event", metadata={"rawBody": "SENTINEL_EVENT_NESTED"})
            print(stream.getvalue())
            """,
            "SENTINEL_EVENT_NESTED",
        )

    def test_log_event_governmentId_dropped(self):
        self._assert_sentinel_absent(
            """\
            import logging, io
            from ocr_worker.logger import setup_logging, log_event

            setup_logging()
            stream = io.StringIO()
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.getLogger().handlers[0].formatter)
            logging.getLogger("ocr_worker.structured").addHandler(handler)
            log_event("test_event", governmentIdentifier="SENTINEL_GOV_ID")
            print(stream.getvalue())
            """,
            "SENTINEL_GOV_ID",
        )


# ===========================================================================
# 8. Positive controls — approved metadata survives
# ===========================================================================


def test_approved_metadata_survives():
    """All approved operational metadata fields survive the sanitiser end-to-end."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, bind_context, log_event, clear_context

        setup_logging()
        bind_context(
            correlationId="550e8400-e29b-41d4-a716-446655440000",
            documentId="doc-456",
            traceId="1-67891233-defdefdefdefdefdefdefdef",
            tenant="platform",
            stage="ocr",
        )

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger("ocr_worker.structured").addHandler(handler)

        log_event(
            "positive_control",
            message_id="550e8400-e29b-41d4-a716-446655440001",
            receive_count=3,
            errorType="ValueError",
            state="OCR_COMPLETED",
            next_stage="classify",
            document_route="default",
            jobId="job-123",
            textractJobId="tj-456",
            downstream_message_id="550e8400-e29b-41d4-a716-446655440002",
            delay=30,
            attempt=2,
            status="SUCCEEDED",
            queue_name="ocr-queue",
            reason="test_reason",
            signal=15,
        )

        clear_context()
        output = stream.getvalue().strip()
        for line in output.splitlines():
            record = json.loads(line)
            assert record.get("correlationId") == "550e8400-e29b-41d4-a716-446655440000"
            assert record.get("documentId") == "doc-456"
            assert record.get("traceId") == "1-67891233-defdefdefdefdefdefdefdef"
            assert record.get("event") == "positive_control"
            assert record.get("state") == "OCR_COMPLETED"
            assert record.get("next_stage") == "classify"
            assert record.get("receive_count") == 3
            assert record.get("errorType") == "ValueError"
            assert record.get("delay") == 30
            assert record.get("attempt") == 2
            assert record.get("jobId") == "job-123"
            assert record.get("textractJobId") == "tj-456"
            assert record.get("downstream_message_id") == "550e8400-e29b-41d4-a716-446655440002"
            assert record.get("status") == "SUCCEEDED"
            assert record.get("message_id") == "550e8400-e29b-41d4-a716-446655440001"
            assert record.get("queue_name") == "ocr-queue"
            assert record.get("reason") == "test_reason"
            assert record.get("signal") == 15
            assert record.get("document_route") == "default"
            print("POSITIVE_CONTROL_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "POSITIVE_CONTROL_OK" in result.stdout


def test_invalidFields_in_safe_error_details():
    """safe_error_details bounded invalidFields survives the sanitiser."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, log_event, safe_error_details

        setup_logging()
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger("ocr_worker.structured").addHandler(handler)

        # Simulate a validation error with invalidFields
        log_event("validation_failed", errorType="ValidationError", errorCount=2,
                  invalidFields=["documentId", "metadata.status"])

        output = stream.getvalue().strip()
        for line in output.splitlines():
            record = json.loads(line)
            assert record.get("errorType") == "ValidationError"
            assert record.get("errorCount") == 2
            assert record.get("invalidFields") == ["documentId", "metadata.status"]
            print("INVALID_FIELDS_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "INVALID_FIELDS_OK" in result.stdout


# ===========================================================================
# 9. Exception redaction
# ===========================================================================


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
            assert "Traceback" not in serialized
        print("LOG_EXCEPTION_REDACTION_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "LOG_EXCEPTION_REDACTION_OK" in result.stdout


# ===========================================================================
# 10. JSON validity
# ===========================================================================


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


# ===========================================================================
# 11. Context cleanup
# ===========================================================================


def test_clear_context_removes_all_fields():
    """clear_context() removes all previously bound fields."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, bind_context, clear_context

        setup_logging()
        bind_context(correlationId="should-vanish", documentId="doc-vanish")

        logger = logging.getLogger("test.ctx")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        clear_context()
        logger.info("after clear")

        output = stream.getvalue().strip()
        for line in output.splitlines():
            record = json.loads(line)
            assert "correlationId" not in record
            assert "documentId" not in record
        print("CLEAR_CONTEXT_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "CLEAR_CONTEXT_OK" in result.stdout


# ===========================================================================
# 12. Combined multi-path redaction (simultaneous context + extra + event)
# ===========================================================================


def test_combined_multi_path_redaction():
    """All three paths combined: context, extra, and event all sanitised."""
    result = _run_python(
        """\
        import json, logging, io
        from ocr_worker.logger import setup_logging, bind_context, log_event, clear_context

        setup_logging()

        # Attempt to inject through context
        bind_context(
            rawBody="CTX_SENTINEL",
            payload="CTX_PAYLOAD_SENTINEL",
            correlationId="550e8400-e29b-41d4-a716-446655440000",
        )

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        logging.getLogger("ocr_worker.structured").addHandler(handler)

        # Attempt to inject through log_event
        log_event(
            "combined_test",
            rawBody="EVENT_RAW_SENTINEL",
            content="EVENT_CONTENT_SENTINEL",
            documentId="doc-safe",
        )

        clear_context()
        output = stream.getvalue().strip()
        for line in output.splitlines():
            if not line.startswith("{"):
                continue
            record = json.loads(line)
            serialized = json.dumps(record)
            assert "CTX_SENTINEL" not in serialized
            assert "CTX_PAYLOAD_SENTINEL" not in serialized
            assert "EVENT_RAW_SENTINEL" not in serialized
            assert "EVENT_CONTENT_SENTINEL" not in serialized
            assert record.get("correlationId") == "550e8400-e29b-41d4-a716-446655440000"
            assert record.get("documentId") is None # DocumentId in event is now dropped
            assert record.get("event") == "combined_test"
        print("COMBINED_REDACTION_OK")
        """,
        pythonpath=str(SRC_DIR),
    )
    assert result.returncode == 0, result.stderr
    assert "COMBINED_REDACTION_OK" in result.stdout


# ===========================================================================
# 13. Message-channel audit
# ===========================================================================


def _check_ast_for_logging_violations(source_code: str, filename: str) -> list[str]:
    import ast

    violations = []
    logger_methods = {"debug", "info", "warning", "warn", "error", "critical", "fatal", "exception"}

    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as exc:
        return [
            f"{filename}:{exc.lineno or 1}: Source could not be parsed by logging audit"
        ]

    logging_modules = {"logging"}
    logger_factories = {"get_logger", "getLogger"}
    logger_aliases = {"logger", "log"}
    logger_attribute_names = {"logger", "_logger", "log", "audit"}
    log_event_aliases = {"log_event"}
    logger_method_aliases: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "logging":
                    logging_modules.add(imported.asname or imported.name)
        elif isinstance(node, ast.ImportFrom):
            for imported in node.names:
                bound_name = imported.asname or imported.name
                if node.module == "logging" and imported.name == "getLogger":
                    logger_factories.add(bound_name)
                elif node.module == "logging" and imported.name in logger_methods:
                    logger_method_aliases.add(bound_name)
                elif imported.name == "get_logger":
                    logger_factories.add(bound_name)
                elif imported.name == "log_event":
                    log_event_aliases.add(bound_name)

    def assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names: list[str] = []
        pending = list(targets)
        while pending:
            target = pending.pop()
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, (ast.List, ast.Tuple)):
                pending.extend(target.elts)
        return names

    def is_logging_module(expr: ast.expr) -> bool:
        return isinstance(expr, ast.Name) and expr.id in logging_modules

    def is_logger_factory_call(expr: ast.expr) -> bool:
        if not isinstance(expr, ast.Call):
            return False
        if isinstance(expr.func, ast.Name):
            return expr.func.id in logger_factories
        return (
            isinstance(expr.func, ast.Attribute)
            and expr.func.attr in {"getLogger", "get_logger"}
            and (
                expr.func.attr == "get_logger"
                or is_logging_module(expr.func.value)
            )
        )

    def is_logger_expression(expr: ast.expr) -> bool:
        return (
            isinstance(expr, ast.Name) and expr.id in logger_aliases
        ) or is_logger_factory_call(expr) or (
            isinstance(expr, ast.Attribute)
            and expr.attr in logger_attribute_names
        )

    def is_log_event_expression(expr: ast.expr) -> bool:
        return (
            isinstance(expr, ast.Name) and expr.id in log_event_aliases
        ) or (
            isinstance(expr, ast.Attribute) and expr.attr == "log_event"
        )

    # Resolve assignment aliases to a fixed point so chains such as
    # ``audit = logger; second = audit`` cannot bypass the audit.
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            targets = assigned_names(node)

            if is_logging_module(value):
                for target in targets:
                    if target not in logging_modules:
                        logging_modules.add(target)
                        changed = True
            if is_logger_expression(value):
                for target in targets:
                    if target not in logger_aliases:
                        logger_aliases.add(target)
                        changed = True
            if is_log_event_expression(value):
                for target in targets:
                    if target not in log_event_aliases:
                        log_event_aliases.add(target)
                        changed = True
            if (
                isinstance(value, ast.Attribute)
                and value.attr in logger_methods
                and (
                    is_logger_expression(value.value)
                    or is_logging_module(value.value)
                )
            ):
                for target in targets:
                    if target not in logger_method_aliases:
                        logger_method_aliases.add(target)
                        changed = True

    def is_safe_string(node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    _ALLOWED_VARS = {
        "documentId": {"documentId", "doc_id"},
        "messageId": {"messageId", "message_id"},
        "message_id": {"messageId", "message_id"},
        "receiveCount": {"receiveCount", "receive_count"},
        "receive_count": {"receiveCount", "receive_count"},
        "errorType": {"errorType", "error_type"},
        "queue": {"queue", "queue_name", "next_stage"},
        "queue_name": {"queue", "queue_name", "next_stage"},
        "jobId": {"jobId", "job_id"},
        "textractJobId": {"textractJobId", "job_id"},
        "document_route": {"document_route"},
        "next_stage": {"next_stage"},
        "status": {"status"},
        "state": {"state"},
        "delay": {"delay_seconds", "delay"},
        "attempt": {"attempt"},
        "signal": {"signal", "signum"},
        "downstream_message_id": {"downstream_message_id"},
    }

    def check_unsafe_expr(
        expr: ast.expr,
        context: str,
        lineno: int,
        kwarg_name: str | None = None,
    ) -> None:
        if isinstance(expr, ast.JoinedStr):
            violations.append(f"{filename}:{lineno}: Disallowed f-string in {context}")
        elif isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Mod):
                violations.append(f"{filename}:{lineno}: Disallowed % formatting in {context}")
            elif isinstance(expr.op, ast.Add):
                violations.append(f"{filename}:{lineno}: Disallowed concatenation in {context}")
        elif isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                violations.append(f"{filename}:{lineno}: Disallowed .format() in {context}")
            elif getattr(expr.func, "id", None) in ("str", "repr", "bytes"):
                violations.append(f"{filename}:{lineno}: Disallowed str() call in {context}")
            elif getattr(expr.func, "id", None) not in ("type", "safe_error_details", "len"):
                if getattr(expr.func, "attr", None) != "__name__":
                    violations.append(f"{filename}:{lineno}: Disallowed function call in {context}")
        elif isinstance(expr, ast.Subscript):
            violations.append(f"{filename}:{lineno}: Disallowed subscript in {context}")
        elif isinstance(expr, ast.Attribute):
            violations.append(f"{filename}:{lineno}: Disallowed attribute access in {context}")
        elif isinstance(expr, ast.Name):
            if kwarg_name in ("reason", "event_name", "event", "message", "msg"):
                violations.append(f"{filename}:{lineno}: Disallowed variable in {context} (must be literal)")
            elif kwarg_name:
                allowed = _ALLOWED_VARS.get(kwarg_name)
                if not allowed or expr.id not in allowed:
                    violations.append(
                        f"{filename}:{lineno}: Disallowed variable name "
                        f"'{expr.id}' for kwarg '{kwarg_name}'"
                    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
            
        is_log_event = (
            isinstance(node.func, ast.Name) and node.func.id in log_event_aliases
        ) or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "log_event"
        )
        is_logger_call = is_log_event or (
            isinstance(node.func, ast.Name)
            and node.func.id in logger_method_aliases
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in logger_methods
            and (
                is_logger_expression(node.func.value)
                or is_logging_module(node.func.value)
            )
        )

        if not is_logger_call:
            if getattr(node.func, "id", None) == "_ScanalyzeEventFields" and not filename.endswith("logger.py"):
                violations.append(f"{filename}:{node.lineno}: _ScanalyzeEventFields must not be constructed manually")
            continue

        msg_arg = None
        if node.args:
            msg_arg = node.args[0]
            if len(node.args) > 1:
                if is_log_event:
                    violations.append(f"{filename}:{node.lineno}: log_event positional metadata is disallowed")
                else:
                    violations.append(
                        f"{filename}:{node.lineno}: "
                        "Logger positional formatting arguments are disallowed"
                    )
        else:
            for kw in node.keywords:
                if kw.arg == "msg" or (is_log_event and kw.arg == "event_name"):
                    msg_arg = kw.value
                    break

        if msg_arg is None:
            violations.append(f"{filename}:{node.lineno}: Missing static log message")
        else:
            if not is_safe_string(msg_arg):
                violations.append(f"{filename}:{node.lineno}: Non-literal log message")
            check_unsafe_expr(msg_arg, "message", node.lineno, "message")

        if is_log_event:
            for kw in node.keywords:
                if kw.arg is None:
                    if isinstance(kw.value, ast.Call) and getattr(kw.value.func, "id", None) == "safe_error_details":
                        pass
                    else:
                        violations.append(f"{filename}:{node.lineno}: Disallowed kwargs unpack in log_event")
                else:
                    check_unsafe_expr(kw.value, f"kwarg '{kw.arg}'", node.lineno, kw.arg)
                    if kw.arg == "reason":
                        if not is_safe_string(kw.value):
                            violations.append(f"{filename}:{node.lineno}: reason kwarg must be a string literal")

    return violations


def test_message_channel_no_payload_interpolation():
    """Log message strings in production code must be static string literals."""
    src_root = SRC_DIR / "ocr_worker"
    violations = []
    
    for py_file in src_root.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        file_violations = _check_ast_for_logging_violations(source, str(py_file.relative_to(REPO_ROOT)))
        violations.extend(file_violations)
            
    assert not violations, (
        "Logger messages must be static string literals:\n" + "\n".join(violations)
    )


def test_ast_audit_negative_snippets():
    """Prove the AST auditor catches negative patterns."""
    snippets = {
        "f-string": "logger.info(f'Hello {name}')",
        "concat": "logger.error('Error: ' + str(e))",
        "format": "logger.warning('Code: {}'.format(code))",
        "percent": "logger.debug('User %s' % user)",
        "variable": "msg = 'bad'; logger.info(msg)",
        "alias_fstring": "log = get_logger(__name__); log.info(f'Fail {x}')",
        "log_event_fstring": "log_event(f'event_{id}')",
        "msg_kwarg": "logger.info(msg=f'test {x}')",
        "log_event_kwarg_fstring": "log_event('event', data=f'val_{x}')",
        "log_event_kwarg_str": "log_event('event', error=str(e))",
        "messageId_wrong_var": "log_event('failure', messageId=payload_alias)",
        "jobId_wrong_var": "log_event('failure', jobId=message_body)",
        "queue_wrong_var": "log_event('failure', queue=customer_content)",
        "status_wrong_var": "log_event('failure', status=payload_alias)",
        "assigned_logger_alias": (
            "audit = logger\n"
            "audit.info(f'payload {payload}')"
        ),
        "logging_module_call": (
            "import logging\n"
            "logging.warning(payload)"
        ),
        "assigned_log_event_alias": (
            "emit = log_event\n"
            "emit(payload)"
        ),
        "chained_get_logger": (
            "import logging\n"
            "logging.getLogger(__name__).error(payload)"
        ),
        "self_logger_attribute": "self.logger.info(payload)",
        "self_private_logger_attribute": "self._logger.error(payload)",
        "nested_audit_attribute": (
            "service.audit.error(f'payload {payload}')"
        ),
        "assigned_attribute_logger_alias": (
            "worker_log = self.logger\n"
            "worker_log.warning(payload)"
        ),
        "assigned_attribute_method_alias": (
            "emit = service.audit.error\n"
            "emit(payload)"
        ),
    }

    for name, code in snippets.items():
        violations = _check_ast_for_logging_violations(code, f"test_{name}.py")
        assert violations, f"AST auditor failed to catch {name} pattern"


def test_ast_audit_fails_closed_on_syntax_error():
    """A source parse failure is itself an audit violation."""
    violations = _check_ast_for_logging_violations(
        "logger.info(",
        "test_syntax_error.py",
    )
    assert violations == [
        "test_syntax_error.py:1: Source could not be parsed by logging audit"
    ]


def test_ast_audit_accepts_supported_static_forms():
    """Alias resolution must preserve legitimate static logging calls."""
    snippets = {
        "assigned_logger_alias": "audit = logger\naudit.info('worker ready')",
        "logging_module_call": "import logging\nlogging.warning('worker waiting')",
        "assigned_log_event_alias": "emit = log_event\nemit('worker_started')",
        "chained_get_logger": (
            "import logging\n"
            "logging.getLogger(__name__).error('worker stopped')"
        ),
        "self_logger_attribute": "self.logger.info('worker ready')",
        "self_private_logger_attribute": "self._logger.error('worker stopped')",
        "nested_audit_attribute": "service.audit.error('audit event')",
        "assigned_attribute_logger_alias": (
            "worker_log = self.logger\n"
            "worker_log.warning('worker waiting')"
        ),
        "assigned_attribute_method_alias": (
            "emit = service.audit.error\n"
            "emit('audit event')"
        ),
    }
    for name, code in snippets.items():
        violations = _check_ast_for_logging_violations(code, f"test_safe_{name}.py")
        assert not violations, f"AST auditor rejected safe {name}: {violations}"


# ===========================================================================
# 14. Sanitiser contract guard
# ===========================================================================


def test_sanitizer_has_allowlist():
    """The logger module defines _SOURCE_PERMISSIONS and _sanitize_log_fields."""
    logger_py = SRC_DIR / "ocr_worker" / "logger.py"
    source = logger_py.read_text(encoding="utf-8")
    assert "_SOURCE_PERMISSIONS" in source, "Logger must define _SOURCE_PERMISSIONS allowlist"
    assert "def _sanitize_log_fields(" in source, "Logger must define _sanitize_log_fields"
    assert source.count("_sanitize_log_fields(") >= 4, (
        "_sanitize_log_fields must be called from bind_context, log_event, and JSONFormatter"
    )
