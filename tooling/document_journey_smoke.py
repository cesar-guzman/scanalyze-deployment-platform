"""Bounded application smoke driver; no infrastructure or identity mutation.

Only the companion, explicitly authorized CLI supplies a real HTTPS transport.
Injected transports are for hermetic tests, never connected-readiness evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit
import uuid

from jsonschema import Draft202012Validator, FormatChecker

from tooling.generate_bank_statement_fixtures import _deterministic_pdf_bytes


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "scanalyze.document-journey.v1"
MAX_BODY = 2 * 1024 * 1024
STEPS = ("CREATE", "UPLOAD", "SUBMIT", "STATUS", "RESULT", "REPLAY")
_CONFIG_FIELDS = frozenset({
    "schema_version", "environment", "processing_domain", "api_origin",
    "upload_host", "deployment_id", "region", "authorization_reference",
    "timeout_seconds", "poll_interval_seconds", "max_requests",
})


class SmokeError(RuntimeError):
    """Only constant public-safe error codes may leave this boundary."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise SmokeError(code)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail("RESPONSE_TIMESTAMP_INVALID")
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise SmokeError("RESPONSE_TIMESTAMP_INVALID") from None


def _url(value: str) -> Any:
    try:
        if not isinstance(value, str) or not value.isascii() or any(
            ord(char) <= 32 or ord(char) == 127 for char in value
        ) or "\\" in value:
            _fail("URL_NOT_ALLOWED")
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.port not in (None, 443) or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or parsed.hostname.endswith(".")):
            _fail("URL_NOT_ALLOWED")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", parsed.hostname):
            _fail("URL_NOT_ALLOWED")
        return parsed
    except ValueError:
        raise SmokeError("URL_NOT_ALLOWED") from None


@dataclass(frozen=True, repr=False)
class SmokeConfig:
    environment: str
    api_origin: str
    upload_host: str
    deployment_id: str
    authorization_reference: str
    timeout_seconds: int
    poll_interval_seconds: int
    max_requests: int

    @classmethod
    def from_dict(cls, value: Any) -> "SmokeConfig":
        if not isinstance(value, dict) or set(value) != _CONFIG_FIELDS:
            _fail("CONFIG_INVALID")
        if (type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["environment"] not in ("dev", "staging")
                or value["processing_domain"] != "bank" or value["region"] != "us-east-1"):
            _fail("TARGET_NOT_ALLOWED")
        for field, lower, upper in (
            ("timeout_seconds", 30, 600), ("poll_interval_seconds", 1, 30),
            ("max_requests", 6, 256),
        ):
            if type(value[field]) is not int or not lower <= value[field] <= upper:
                _fail("CONFIG_BUDGET_INVALID")
        for field, pattern in (
            ("deployment_id", r"dep_[0-9A-HJKMNP-TV-Z]{26}"),
            ("authorization_reference", r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"),
            ("upload_host", r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.us-east-1\.amazonaws\.com"),
        ):
            if not isinstance(value[field], str) or not re.fullmatch(pattern, value[field]):
                _fail("CONFIG_INVALID")
        origin = _url(value["api_origin"])
        if origin.path or origin.query or value["api_origin"] != "https://" + origin.hostname:
            _fail("API_ORIGIN_INVALID")
        if origin.hostname == value["upload_host"]:
            _fail("API_ORIGIN_INVALID")
        return cls(**{key: value[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True, repr=False)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None, timeout: float) -> HttpResponse: ...


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, timeout: float):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class HttpsTransport:
    """No proxies, redirects, cookies, alternate CA, or private-address targets."""

    def request(self, method: str, url: str, headers: Mapping[str, str],
                body: bytes | None, timeout: float) -> HttpResponse:
        connection = None
        deadline = time.monotonic() + timeout
        try:
            if any(os.environ.get(name) for name in (
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
            )):
                _fail("TRANSPORT_ENVIRONMENT_UNSAFE")
            parsed = _url(url)
            addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
                _fail("ADDRESS_NOT_ALLOWED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("TIME_BUDGET_EXHAUSTED")
            connection = _PinnedConnection(parsed.hostname, addresses[0][4][0], remaining)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            if response.getheader("Content-Encoding", "identity") != "identity":
                _fail("RESPONSE_ENCODING_UNSUPPORTED")
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail("TIME_BUDGET_EXHAUSTED")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(65_536, MAX_BODY + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_BODY:
                    _fail("RESPONSE_TOO_LARGE")
            payload = b"".join(chunks)
            return HttpResponse(response.status, {
                "content-type": response.getheader("Content-Type", ""),
            }, payload)
        except SmokeError:
            raise
        except Exception:
            raise SmokeError("REQUEST_OUTCOME_UNKNOWN") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    raise SmokeError("REQUEST_OUTCOME_UNKNOWN") from None


def synthetic_pdf() -> bytes:
    """A deterministic fictional statement; no arbitrary document input is accepted."""
    return _deterministic_pdf_bytes("\n".join((
        "SYNTHETIC TEST ONLY - NOT A REAL FINANCIAL RECORD",
        "Scanalyze Synthetic Bank", "Bank statement - January 2026",
        "Account holder: SYNTHETIC TEST ONLY", "Account: 000000000000",
        "Currency: MXN", "Period: 2026-01-01 to 2026-01-31",
        "Opening balance: 0.00", "Transactions:",
        "Date: 2026-01-01  Reference: E2E-0001",
        "Description: SYNTHETIC TEST ONLY",
        "Direction: credit  Amount: 100.00  Balance after: 100.00",
        "Total credits: 100.00  Total debits: 0.00", "Closing balance: 100.00",
        "All values are fictional and intended only for authorized testing.",
    )))


def _json(payload: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("RESPONSE_JSON_INVALID")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: _fail("RESPONSE_JSON_INVALID"))
        if not isinstance(value, dict):
            _fail("RESPONSE_JSON_INVALID")
        stack = [(value, 0)]
        while stack:
            node, depth = stack.pop()
            if depth > 80 or isinstance(node, float) and not math.isfinite(node):
                _fail("RESPONSE_JSON_INVALID")
            if isinstance(node, dict):
                stack.extend((item, depth + 1) for item in node.values())
            elif isinstance(node, list):
                stack.extend((item, depth + 1) for item in node)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise SmokeError("RESPONSE_JSON_INVALID") from None


class _Contracts:
    def __init__(self) -> None:
        try:
            self.openapi = json.loads((ROOT / "schemas/scanalyze-document-journey.openapi.v1.json").read_text())
            self.result = json.loads((ROOT / "schemas/scanalyze-document-journey-result.v1.schema.json").read_text())
        except (OSError, ValueError):
            raise SmokeError("SOURCE_CONTRACT_UNAVAILABLE") from None

    def validate(self, name: str, value: dict[str, Any]) -> None:
        schema = self.result if name == "Result" else {
            "$ref": "#/components/schemas/" + name,
            "components": self.openapi["components"],
        }
        try:
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            if next(validator.iter_errors(value), None) is not None:
                _fail("RESPONSE_SCHEMA_INVALID")
        except SmokeError:
            raise
        except Exception:
            raise SmokeError("RESPONSE_SCHEMA_INVALID") from None


def _result_semantics(value: dict[str, Any]) -> None:
    data = value["data"]
    balances = data["balances"]
    transactions = data["transactions"]
    if (value["warnings"] or value["quality"]["overallConfidence"] < 90
            or data["bank"]["name"] != "Scanalyze Synthetic Bank"
            or data["account"]["currency"] != "MXN"
            or data["statement"] != {"periodStart": "2026-01-01", "periodEnd": "2026-01-31"}
            or any(balances[key] != expected for key, expected in (
                ("opening", 0), ("closing", 100), ("totalCredits", 100), ("totalDebits", 0)))
            or len(transactions) != 1):
        _fail("SYNTHETIC_RESULT_MISMATCH")
    transaction = transactions[0]
    if any(transaction[key] != expected for key, expected in (
        ("date", "2026-01-01"), ("reference", "E2E-0001"), ("direction", "credit"),
        ("amount", 100), ("balanceAfter", 100),
    )):
        _fail("SYNTHETIC_RESULT_MISMATCH")


def run_smoke(
    config: SmokeConfig, access_token: str, transport: Transport, *,
    on_progress: Callable[[dict[str, Any]], None] = lambda _event: None,
    on_recovery: Callable[[dict[str, Any]], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """One bounded positive API journey. Does not certify isolation or production."""
    if not callable(on_recovery):
        _fail("RECOVERY_JOURNAL_REQUIRED")
    if (not isinstance(access_token, str) or not 16 <= len(access_token) <= 16_384
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", access_token)):
        _fail("ACCESS_TOKEN_INVALID")
    contracts = _Contracts()
    document = synthetic_pdf()
    start = clock()
    requests = 0
    completed: list[str] = []
    key = str(uuid.uuid4())
    api_headers = {"Authorization": "Bearer " + access_token,
                   "X-Scanalyze-Contract-Version": CONTRACT,
                   "Content-Type": "application/json", "Accept": "application/json"}

    def emit(event: dict[str, Any]) -> None:
        try:
            on_progress(event)
        except Exception:
            raise SmokeError("JOURNAL_WRITE_FAILED") from None

    def recoverable(event: dict[str, Any]) -> None:
        # Private recovery coordinates are separate from public progress/summary.
        # The connected CLI durably writes each event before allowing more HTTP.
        try:
            on_recovery(event)
        except Exception:
            raise SmokeError("JOURNAL_WRITE_FAILED") from None

    def remaining() -> float:
        value = config.timeout_seconds - (clock() - start)
        if value <= 0:
            _fail("TIME_BUDGET_EXHAUSTED")
        return value

    def call(stage: str, method: str, url: str, headers: Mapping[str, str],
             body: bytes | None, expected: int, schema: str | None) -> dict[str, Any]:
        nonlocal requests
        if requests >= config.max_requests:
            _fail("REQUEST_BUDGET_EXHAUSTED")
        remaining()
        requests += 1
        emit({"stage": stage, "requests": requests, "status": "BEFORE_REQUEST"})
        timeout = min(30.0, remaining())
        try:
            response = transport.request(method, url, headers, body, timeout)
        except SmokeError:
            raise
        except Exception:
            raise SmokeError("REQUEST_OUTCOME_UNKNOWN") from None
        remaining()
        if response.status != expected:
            _fail("HTTP_STATUS_UNEXPECTED")
        if not isinstance(response.body, bytes) or len(response.body) > MAX_BODY:
            _fail("RESPONSE_TOO_LARGE")
        if schema is None:
            return {}
        media_type = next((v for k, v in response.headers.items() if k.lower() == "content-type"), "")
        if media_type.split(";", 1)[0].strip().lower() != "application/json":
            _fail("RESPONSE_MEDIA_TYPE_INVALID")
        value = _json(response.body)
        contracts.validate(schema, value)
        return value

    def passed(stage: str) -> None:
        completed.append(stage)
        emit({"stage": stage, "requests": requests, "status": "STEP_PASSED"})

    payload = json.dumps({"filename": "scanalyze-synthetic-smoke.pdf",
                          "contentType": "application/pdf", "contentLength": len(document)},
                         separators=(",", ":")).encode()
    create_headers = {**api_headers, "Idempotency-Key": key}
    create_url = config.api_origin + "/api/v2/documents"
    recoverable({"event": "CREATE_PREPARED", "idempotency_key": key,
                 "request_sha256": _sha(payload)})
    created = call("CREATE", "POST", create_url, create_headers, payload, 201, "DocumentCreateResponse")
    if created["replayed"] is not False or created["durableResponse"]["contentType"] != "application/pdf":
        _fail("CREATE_RESPONSE_MISMATCH")
    durable = created["durableResponse"]
    document_id = durable["documentId"]
    created_at = _utc(durable["createdAt"])
    if created_at > utcnow():
        _fail("RESPONSE_TIMESTAMP_INVALID")
    recoverable({"event": "DOCUMENT_CREATED", "document_id": document_id})
    passed("CREATE")
    capability = created["uploadCapability"]
    parsed = _url(capability["url"])
    if (parsed.hostname != config.upload_host or not parsed.path or not parsed.query
            or capability["requiredHeaders"] != {"Content-Type": "application/pdf"}
            or _utc(capability["expiresAt"]) <= utcnow()):
        _fail("UPLOAD_CAPABILITY_NOT_ALLOWED")
    call("UPLOAD", "PUT", capability["url"], {"Content-Type": "application/pdf"},
         document, 200, None)
    passed("UPLOAD")
    document_url = config.api_origin + "/api/v2/documents/" + document_id
    submitted = call("SUBMIT", "POST", document_url + "/submit", api_headers,
                     b'{"stage":"ingest"}', 202, "SubmitDocumentResponse")
    if submitted["documentId"] != document_id:
        _fail("DOCUMENT_ID_MISMATCH")
    passed("SUBMIT")
    updated_at = created_at
    while True:
        observed = call("STATUS", "GET", document_url, api_headers, None, 200, "DocumentStatusResponse")
        new_updated_at = _utc(observed["updatedAt"])
        if observed["documentId"] != document_id:
            _fail("DOCUMENT_ID_MISMATCH")
        if (_utc(observed["createdAt"]) != created_at or new_updated_at < updated_at
                or new_updated_at > utcnow()):
            _fail("RESPONSE_TIMESTAMP_INVALID")
        updated_at = new_updated_at
        if observed["lifecycle"] == "FAILED" or observed["stageState"] == "FAILED":
            _fail("DOCUMENT_PROCESSING_FAILED")
        if observed["lifecycle"] == "COMPLETED":
            if not created_at <= _utc(observed["terminalAt"]) <= updated_at:
                _fail("RESPONSE_TIMESTAMP_INVALID")
            break
        if observed["processingCondition"] != "ACTIVE":
            _fail("PROCESSING_NOT_ACTIVE")
        sleep(min(config.poll_interval_seconds, remaining()))
    passed("STATUS")
    result = call("RESULT", "GET", document_url + "/result", api_headers, None, 200, "Result")
    if result["documentId"] != document_id or result["resultId"] != "result_" + document_id + "_v1":
        _fail("DOCUMENT_ID_MISMATCH")
    if not created_at <= _utc(result["provenance"]["generatedAt"]) <= utcnow():
        _fail("RESPONSE_TIMESTAMP_INVALID")
    _result_semantics(result)
    passed("RESULT")
    replay = call("REPLAY", "POST", create_url, create_headers, payload, 201, "DocumentCreateResponse")
    if replay["replayed"] is not True or replay["durableResponse"] != durable:
        _fail("IDEMPOTENCY_REPLAY_MISMATCH")
    passed("REPLAY")
    return {"schema_version": 1, "status": "APPLICATION_SMOKE_PASSED",
            "scope": "single_synthetic_bank_document", "production_authorized": False,
            "requests": requests, "completed_steps": completed,
            "document_id_sha256": _sha(document_id.encode()), "pdf_sha256": _sha(document),
            "elapsed_milliseconds": int((clock() - start) * 1000)}
