from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

import app.api.v2.router as journey_routes
from app.auth import AuthContext, get_auth_context
from app.errors import AppError, register_exception_handlers
from app.journey_contract import (
    CONTRACT_HEADER,
    CONTRACT_VERSION,
    IDEMPOTENCY_HEADER,
    BatchCreateResponse,
    BatchDurableResponse,
    DocumentCreateResponse,
    DocumentDurableResponse,
    DocumentStatusResponse,
    ErrorCode,
    LedgerState,
    OperationKind,
    ReconciliationResponse,
    UploadCapability,
    UploadRequiredHeaders,
)
from app.main import app as legacy_application
from app.middleware import RequestContextMiddleware


NOW = datetime(2026, 8, 7, 18, 0, tzinfo=timezone.utc)
KEY = "00000000-0000-4000-8000-000000000001"
DOCUMENT_ID = "00000000000000000000000000000001"
BATCH_ID = "00000000000000000000000000000002"
ORIGIN = "https://ui.synthetic.invalid"


def _auth() -> AuthContext:
    return AuthContext(
        customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
        deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        principal_type="user",
        subject="synthetic-route-actor",
        client_id=None,
        scopes=(),
        granted_actions=(),
        email=None,
        name=None,
        auth_source="synthetic-test",
    )


class StubJourneyService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.failure: AppError | None = None
        self.replay_document = False

    def _record(self, name: str, arguments: dict[str, Any]) -> None:
        self.calls.append((name, arguments))
        if self.failure is not None:
            error = self.failure
            self.failure = None
            raise error

    def create_batch(self, **arguments: Any) -> BatchCreateResponse:
        self._record("create_batch", arguments)
        return BatchCreateResponse(
            replayed=False,
            durable_response=BatchDurableResponse(
                batchId=BATCH_ID,
                createdAt=NOW,
            ),
        )

    def create_document(self, **arguments: Any) -> DocumentCreateResponse:
        self._record("create_document", arguments)
        return DocumentCreateResponse(
            replayed=self.replay_document,
            durable_response=DocumentDurableResponse(
                documentId=DOCUMENT_ID,
                contentType="application/pdf",
                createdAt=NOW,
            ),
            uploadCapability=(
                None
                if self.replay_document
                else UploadCapability(
                    url="https://upload.invalid/synthetic-capability",
                    expiresAt=NOW,
                    requiredHeaders=UploadRequiredHeaders(
                        **{"Content-Type": "application/pdf"}
                    ),
                )
            ),
        )

    def get_document_status(self, **arguments: Any) -> DocumentStatusResponse:
        self._record("get_document_status", arguments)
        return DocumentStatusResponse(
            documentId=DOCUMENT_ID,
            lifecycle="UPLOAD_PENDING",
            currentStage="INGEST",
            stageState="PENDING",
            processingCondition="ACTIVE",
            createdAt=NOW,
            updatedAt=NOW,
        )

    def reconcile(self, **arguments: Any) -> ReconciliationResponse:
        self._record("reconcile", arguments)
        return ReconciliationResponse(
            operation=arguments["operation"],
            ledgerState=LedgerState.PENDING,
            createdAt=NOW,
            updatedAt=NOW,
            expiresAt=NOW + timedelta(hours=1),
        )


@pytest.fixture
def route_client() -> tuple[TestClient, StubJourneyService, FastAPI]:
    service = StubJourneyService()
    auth = _auth()
    application = FastAPI()
    application.add_middleware(
        RequestContextMiddleware,
        service_name="synthetic-journey-route",
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[ORIGIN],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-Correlation-ID",
            "X-Scanalyze-Contract-Version",
        ],
        expose_headers=[
            "Retry-After",
            "X-Correlation-ID",
            "X-Request-ID",
            "X-Trace-ID",
        ],
    )
    application.include_router(journey_routes.router)
    register_exception_handlers(application)
    application.dependency_overrides[journey_routes._svc] = lambda: service
    application.dependency_overrides[get_auth_context] = lambda: auth
    for dependency in (
        journey_routes._CREATE_BATCH_ACCESS,
        journey_routes._CREATE_DOCUMENT_ACCESS,
        journey_routes._SUBMIT_DOCUMENT_ACCESS,
        journey_routes._READ_DOCUMENT_ACCESS,
        journey_routes._READ_FULL_RESULT_ACCESS,
        journey_routes._reconciliation_access,
    ):
        application.dependency_overrides[dependency] = lambda: auth
    with TestClient(application, raise_server_exceptions=False) as client:
        yield client, service, application


def _headers(*, origin: bool = False) -> dict[str, str]:
    result = {
        CONTRACT_HEADER: CONTRACT_VERSION,
        IDEMPOTENCY_HEADER: KEY,
        "Content-Type": "application/json",
    }
    if origin:
        result["Origin"] = ORIGIN
    return result


def _assert_closed_error(response: Any, *, code: str, status: int) -> dict[str, Any]:
    assert response.status_code == status
    body = response.json()
    assert body["schemaVersion"] == "scanalyze.error.v1"
    assert body["code"] == code
    assert body["correlationId"].startswith("ref_")
    assert len(body["correlationId"]) == 36
    assert response.headers["X-Correlation-ID"] == body["correlationId"]
    assert body["retryClass"] in {
        "NOT_RETRYABLE",
        "RETRYABLE_WITH_BACKOFF",
        "RETRY_ONLY_AFTER_RECONCILIATION",
        "TERMINAL",
        "UNKNOWN_OR_QUARANTINED",
    }
    assert set(body).issubset(
        {"schemaVersion", "code", "message", "correlationId", "retryClass", "details"}
    )
    return body


def test_version_and_idempotency_headers_are_mandatory_and_exact(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    missing_version = client.post(
        "/api/v2/batches",
        content=b"{}",
        headers={IDEMPOTENCY_HEADER: KEY, "Content-Type": "application/json"},
    )
    _assert_closed_error(
        missing_version, code="UNSUPPORTED_CONTRACT_VERSION", status=400
    )

    wrong_version = client.post(
        "/api/v2/batches",
        content=b"{}",
        headers={
            CONTRACT_HEADER: "scanalyze.document-journey.v2",
            IDEMPOTENCY_HEADER: KEY,
            "Content-Type": "application/json",
        },
    )
    _assert_closed_error(
        wrong_version, code="UNSUPPORTED_CONTRACT_VERSION", status=400
    )

    missing_key = client.post(
        "/api/v2/batches",
        content=b"{}",
        headers={CONTRACT_HEADER: CONTRACT_VERSION, "Content-Type": "application/json"},
    )
    _assert_closed_error(missing_key, code="MALFORMED_REQUEST", status=400)

    malformed_key = client.post(
        "/api/v2/batches",
        content=b"{}",
        headers={
            CONTRACT_HEADER: CONTRACT_VERSION,
            IDEMPOTENCY_HEADER: "not-a-uuid",
            "Content-Type": "application/json",
        },
    )
    _assert_closed_error(malformed_key, code="MALFORMED_REQUEST", status=400)
    assert service.calls == []


def test_strict_json_rejects_duplicate_keys_unknown_fields_and_wrong_media_type(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    duplicate = client.post(
        "/api/v2/documents",
        content=(
            b'{"contentType":"application/pdf",'
            b'"contentType":"image/png"}'
        ),
        headers=_headers(),
    )
    duplicate_body = _assert_closed_error(
        duplicate, code="MALFORMED_REQUEST", status=400
    )
    assert duplicate_body["details"] == {"field": "body"}

    unknown = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf", "unreviewed": True},
        headers={
            CONTRACT_HEADER: CONTRACT_VERSION,
            IDEMPOTENCY_HEADER: KEY,
        },
    )
    _assert_closed_error(unknown, code="MALFORMED_REQUEST", status=400)

    wrong_media = client.post(
        "/api/v2/documents",
        content=b'{"contentType":"application/pdf"}',
        headers={
            CONTRACT_HEADER: CONTRACT_VERSION,
            IDEMPOTENCY_HEADER: KEY,
            "Content-Type": "text/plain",
        },
    )
    _assert_closed_error(wrong_media, code="MALFORMED_REQUEST", status=400)
    assert service.calls == []


def test_runtime_rejects_non_wire_aliases_whitespace_filename_and_null_stage(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    snake_case = client.post(
        "/api/v2/documents",
        json={"content_type": "application/pdf"},
        headers=_headers(),
    )
    whitespace_filename = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf", "filename": "   "},
        headers=_headers(),
    )
    dot_segment_filename = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf", "filename": " .. "},
        headers=_headers(),
    )
    null_stage = client.post(
        f"/api/v2/documents/{DOCUMENT_ID}/submit",
        json={"stage": None},
        headers={
            CONTRACT_HEADER: CONTRACT_VERSION,
            "Content-Type": "application/json",
        },
    )

    _assert_closed_error(snake_case, code="MALFORMED_REQUEST", status=400)
    _assert_closed_error(
        whitespace_filename,
        code="SEMANTIC_VALIDATION_FAILED",
        status=422,
    )
    _assert_closed_error(
        dot_segment_filename,
        code="SEMANTIC_VALIDATION_FAILED",
        status=422,
    )
    _assert_closed_error(
        null_stage,
        code="SEMANTIC_VALIDATION_FAILED",
        status=422,
    )
    assert service.calls == []


def test_duplicate_idempotency_headers_are_rejected_as_ambiguous(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client
    response = client.post(
        "/api/v2/batches",
        content=b"{}",
        headers=[
            (CONTRACT_HEADER, CONTRACT_VERSION),
            (IDEMPOTENCY_HEADER, KEY),
            (IDEMPOTENCY_HEADER, "00000000-0000-4000-8000-000000000002"),
            ("Content-Type", "application/json"),
        ],
    )

    _assert_closed_error(response, code="MALFORMED_REQUEST", status=400)
    assert service.calls == []


@pytest.mark.parametrize(
    ("duplicate_header", "first", "second", "code"),
    [
        (
            CONTRACT_HEADER,
            CONTRACT_VERSION,
            CONTRACT_VERSION,
            "UNSUPPORTED_CONTRACT_VERSION",
        ),
        (
            IDEMPOTENCY_HEADER,
            KEY,
            "00000000-0000-4000-8000-000000000002",
            "MALFORMED_REQUEST",
        ),
        ("Content-Type", "application/json", "application/json", "MALFORMED_REQUEST"),
        (
            "X-Correlation-ID",
            "synthetic-correlation-one",
            "synthetic-correlation-two",
            "MALFORMED_REQUEST",
        ),
    ],
)
def test_duplicate_contract_transport_headers_are_rejected(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
    duplicate_header: str,
    first: str,
    second: str,
    code: str,
) -> None:
    client, service, _application = route_client
    headers = [
        (CONTRACT_HEADER, CONTRACT_VERSION),
        (IDEMPOTENCY_HEADER, KEY),
        ("Content-Type", "application/json"),
    ]
    headers = [(name, value) for name, value in headers if name != duplicate_header]
    headers.extend(((duplicate_header, first), (duplicate_header, second)))

    response = client.post("/api/v2/batches", content=b"{}", headers=headers)

    _assert_closed_error(response, code=code, status=400)
    assert service.calls == []


@pytest.mark.parametrize(
    ("headers", "code", "status"),
    [
        (
            [(b"x-tenant-id", b"attacker-selected-owner")],
            "AUTHORIZATION_DENIED",
            403,
        ),
        (
            [
                (b"authorization", b"Bearer synthetic-one"),
                (b"authorization", b"Bearer synthetic-two"),
            ],
            "AUTHENTICATION_INVALID",
            401,
        ),
    ],
)
def test_legacy_authority_and_ambiguous_auth_headers_are_rejected_before_auth(
    monkeypatch: pytest.MonkeyPatch,
    headers: list[tuple[bytes, bytes]],
    code: str,
    status: int,
) -> None:
    request = journey_routes.Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v2/batches",
            "headers": headers,
            "query_string": b"",
            "scheme": "https",
            "server": ("synthetic.invalid", 443),
            "client": ("127.0.0.1", 1),
        }
    )
    monkeypatch.setattr(journey_routes, "get_auth_context", lambda **_kwargs: _auth())

    with pytest.raises(AppError) as captured:
        journey_routes._v2_auth_context(request)

    assert captured.value.code == code
    assert captured.value.status_code == status


def test_success_response_is_closed_and_uses_canonical_casing(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(origin=True),
    )

    assert response.status_code == 201
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["X-Correlation-ID"].startswith("ref_")
    assert len(response.headers["X-Correlation-ID"]) == 36
    body = response.json()
    assert set(body) == {
        "schemaVersion",
        "contractVersion",
        "replayed",
        "durableResponse",
        "uploadCapability",
    }
    assert body["contractVersion"] == CONTRACT_VERSION
    assert body["durableResponse"]["documentId"] == DOCUMENT_ID
    assert body["durableResponse"]["status"] == "UPLOAD_PENDING"
    assert "batchId" not in body["durableResponse"]
    assert body["uploadCapability"]["method"] == "PUT"
    assert body["uploadCapability"]["requiredHeaders"] == {
        "Content-Type": "application/pdf"
    }
    assert service.calls[0][0] == "create_document"
    assert service.calls[0][1]["idempotency_key"] == KEY


def test_replayed_document_omits_absent_upload_capability_on_wire(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client
    service.replay_document = True

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["replayed"] is True
    assert "uploadCapability" not in body
    assert "batchId" not in body["durableResponse"]


def test_reconciliation_omits_absent_state_fields_on_wire(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    response = client.post(
        "/api/v2/operations/documents.create/reconciliation",
        headers={
            CONTRACT_HEADER: CONTRACT_VERSION,
            IDEMPOTENCY_HEADER: KEY,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["operation"] == OperationKind.DOCUMENT_CREATE.value
    assert body["ledgerState"] == LedgerState.PENDING.value
    assert {
        "durableResponse",
        "failureCode",
        "completedAt",
    }.isdisjoint(body)
    assert service.calls[-1][0] == "reconcile"


def test_document_status_omits_absent_projection_fields_on_wire(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    response = client.get(
        f"/api/v2/documents/{DOCUMENT_ID}",
        headers={CONTRACT_HEADER: CONTRACT_VERSION},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["documentId"] == DOCUMENT_ID
    assert {
        "batchId",
        "terminalAt",
        "correlationReference",
        "progress",
        "failureDisposition",
        "safeFailureCode",
    }.isdisjoint(body)
    assert service.calls[-1][0] == "get_document_status"


def test_client_correlation_value_is_pseudonymized_before_response(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, _service, _application = route_client
    external_reference = "external-customer-correlation-123"
    headers = _headers()
    headers["X-Correlation-ID"] = external_reference

    response = client.post("/api/v2/batches", content=b"{}", headers=headers)

    assert response.status_code == 201
    assert response.headers["X-Correlation-ID"].startswith("ref_")
    assert response.headers["X-Correlation-ID"] != external_reference
    assert external_reference not in response.text


def test_app_errors_are_mapped_to_reviewed_message_and_never_echo_provider_text(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client
    service.failure = AppError(
        code="IDEMPOTENCY_CONFLICT",
        message="synthetic provider secret and raw request must not escape",
        status_code=409,
        details={"operation": "documents.create", "provider": "hidden"},
    )

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(),
    )

    body = _assert_closed_error(response, code="IDEMPOTENCY_CONFLICT", status=409)
    assert body["message"] == "The idempotency key is bound to a different request."
    assert body["details"] == {"operation": "documents.create"}
    assert "provider" not in response.text
    assert "secret" not in response.text


_EXPECTED_ERROR_POLICY = {
    "MALFORMED_REQUEST": (400, "The request is malformed.", "NOT_RETRYABLE"),
    "AUTHENTICATION_REQUIRED": (401, "Authentication is required.", "NOT_RETRYABLE"),
    "AUTHENTICATION_INVALID": (401, "Authentication is invalid.", "NOT_RETRYABLE"),
    "AUTHORIZATION_DENIED": (403, "The operation is not authorized.", "TERMINAL"),
    "NOT_FOUND": (404, "The requested resource was not found.", "TERMINAL"),
    "IDEMPOTENCY_CONFLICT": (
        409,
        "The idempotency key is bound to a different request.",
        "TERMINAL",
    ),
    "STATE_CONFLICT": (
        409,
        "The resource state conflicts with this operation.",
        "TERMINAL",
    ),
    "RESULT_NOT_READY": (
        409,
        "The document result is not ready.",
        "RETRYABLE_WITH_BACKOFF",
    ),
    "SEMANTIC_VALIDATION_FAILED": (
        422,
        "The request failed semantic validation.",
        "NOT_RETRYABLE",
    ),
    "RATE_LIMITED": (
        429,
        "The request rate is limited.",
        "RETRYABLE_WITH_BACKOFF",
    ),
    "INTERNAL_ERROR": (
        500,
        "The service could not complete the request.",
        "UNKNOWN_OR_QUARANTINED",
    ),
    "UPSTREAM_ERROR": (
        502,
        "A required service failed.",
        "RETRYABLE_WITH_BACKOFF",
    ),
    "SERVICE_UNAVAILABLE": (
        503,
        "The service is temporarily unavailable.",
        "RETRYABLE_WITH_BACKOFF",
    ),
    "REQUEST_TIMEOUT": (
        503,
        "The request outcome is not confirmed.",
        "RETRY_ONLY_AFTER_RECONCILIATION",
    ),
    "UNSUPPORTED_CONTRACT_VERSION": (
        400,
        "The contract version is not supported.",
        "NOT_RETRYABLE",
    ),
    "UNKNOWN_WRITE_OUTCOME": (
        500,
        "The write outcome requires reconciliation.",
        "RETRY_ONLY_AFTER_RECONCILIATION",
    ),
    "UNSUPPORTED_STATE": (
        500,
        "The resource state is not supported.",
        "UNKNOWN_OR_QUARANTINED",
    ),
    "MALFORMED_INTERNAL_RESULT": (
        500,
        "The document result is invalid.",
        "UNKNOWN_OR_QUARANTINED",
    ),
    "EXPIRED_OPERATION": (
        409,
        "The operation key has expired.",
        "TERMINAL",
    ),
    "UNSUPPORTED_RESULT_TYPE": (
        422,
        "The document result type is not supported.",
        "TERMINAL",
    ),
}


@pytest.mark.parametrize("code", sorted(_EXPECTED_ERROR_POLICY))
def test_every_error_class_has_exact_safe_policy_retry_and_header_behavior(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
    code: str,
) -> None:
    client, service, _application = route_client
    expected_status, expected_message, expected_retry_class = _EXPECTED_ERROR_POLICY[
        code
    ]
    service.failure = AppError(
        code=code,
        message=(
            "Bearer secret-token arn:aws:sqs:region:account:queue "
            "https://signed.invalid/?X-Amz-Signature=secret raw document PII"
        ),
        status_code=expected_status,
        details={
            "operation": "documents.create",
            "provider": "raw provider response synthetic.person@example.invalid",
            "retryAfterSeconds": 19,
        },
        retry_after_seconds=19,
    )

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(),
    )

    body = _assert_closed_error(response, code=code, status=expected_status)
    assert body == {
        "schemaVersion": "scanalyze.error.v1",
        "code": code,
        "message": expected_message,
        "correlationId": body["correlationId"],
        "retryClass": expected_retry_class,
        "details": {
            "operation": "documents.create",
            **(
                {"retryAfterSeconds": 19}
                if code in {"RATE_LIMITED", "SERVICE_UNAVAILABLE"}
                else {}
            ),
        },
    }
    if code in {"RATE_LIMITED", "SERVICE_UNAVAILABLE"}:
        assert response.headers["Retry-After"] == "19"
    else:
        assert "Retry-After" not in response.headers
    lowered = response.text.lower()
    for forbidden in (
        "secret-token",
        "arn:aws",
        "x-amz-signature",
        "raw document",
        "synthetic.person@example.invalid",
        "provider",
    ):
        assert forbidden not in lowered


def test_error_policy_matrix_covers_every_declared_public_code() -> None:
    assert set(_EXPECTED_ERROR_POLICY) == {member.value for member in ErrorCode}


@pytest.mark.parametrize("invalid_retry_after", [0, -1, 3601, True, "19"])
def test_retry_after_rejects_unbounded_or_noninteger_hints(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
    invalid_retry_after: object,
) -> None:
    client, service, _application = route_client
    service.failure = AppError(
        code="SERVICE_UNAVAILABLE",
        message="unsafe provider text",
        status_code=503,
        details={"retryAfterSeconds": invalid_retry_after},
        retry_after_seconds=invalid_retry_after,  # type: ignore[arg-type]
    )

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(),
    )

    body = _assert_closed_error(
        response,
        code="SERVICE_UNAVAILABLE",
        status=503,
    )
    assert "Retry-After" not in response.headers
    assert "details" not in body


def test_unhandled_provider_exception_is_redacted_to_supported_internal_error(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client
    service.failure = RuntimeError(
        "Bearer secret-token arn:aws:sqs:region:account:queue raw document PII"
    )  # type: ignore[assignment]

    response = client.post(
        "/api/v2/documents",
        json={"contentType": "application/pdf"},
        headers=_headers(),
    )

    body = _assert_closed_error(response, code="INTERNAL_ERROR", status=500)
    assert body["message"] == "The service could not complete the request."
    lowered = response.text.lower()
    assert "secret-token" not in lowered
    assert "arn:aws" not in lowered
    assert "raw document" not in lowered


def test_path_and_operation_validation_use_closed_error_envelopes(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, service, _application = route_client

    bad_document = client.get(
        "/api/v2/documents/not-a-document-id",
        headers={CONTRACT_HEADER: CONTRACT_VERSION},
    )
    _assert_closed_error(
        bad_document, code="SEMANTIC_VALIDATION_FAILED", status=422
    )

    bad_operation = client.post(
        "/api/v2/operations/unreviewed.create/reconciliation",
        headers={CONTRACT_HEADER: CONTRACT_VERSION, IDEMPOTENCY_HEADER: KEY},
    )
    _assert_closed_error(
        bad_operation, code="SEMANTIC_VALIDATION_FAILED", status=422
    )
    assert service.calls == []


def test_cors_preflight_allows_only_the_reviewed_contract_headers(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    client, _service, _application = route_client
    response = client.options(
        "/api/v2/documents",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "authorization,content-type,idempotency-key,x-correlation-id,"
                "x-scanalyze-contract-version"
            ),
        },
    )

    assert response.status_code == 200
    allowed = response.headers["access-control-allow-headers"].lower()
    for header in (
        "authorization",
        "content-type",
        "idempotency-key",
        "x-correlation-id",
        "x-scanalyze-contract-version",
    ):
        assert header in allowed
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


def test_runtime_openapi_omits_v2_paths_from_legacy_generated_schema(
    route_client: tuple[TestClient, StubJourneyService, FastAPI],
) -> None:
    _client, _service, application = route_client
    schema = application.openapi()

    assert schema["paths"] == {}
    assert not any(
        path.startswith("/api/v2")
        for path in legacy_application.openapi()["paths"]
    )


def test_committed_openapi_is_the_explicit_v2_journey_authority() -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[4]
            / "schemas/scanalyze-document-journey.openapi.v1.json"
        ).read_text(encoding="utf-8")
    )
    expected_paths = {
        "/api/v2/batches",
        "/api/v2/documents",
        "/api/v2/documents/{documentId}/submit",
        "/api/v2/documents/{documentId}",
        "/api/v2/documents/{documentId}/upload-capabilities",
        "/api/v2/operations/{operation}/reconciliation",
        "/api/v2/documents/{documentId}/result",
    }

    assert set(schema["paths"]) == expected_paths
    assert "x-tenant-id" not in str(schema).lower()


def test_route_endpoints_that_call_blocking_sdk_services_are_synchronous() -> None:
    for endpoint in (
        journey_routes.create_batch,
        journey_routes.create_document,
        journey_routes.submit_document,
        journey_routes.get_document_status,
        journey_routes.refresh_upload_capability,
        journey_routes.reconcile_operation,
        journey_routes.get_result,
    ):
        assert inspect.iscoroutinefunction(endpoint) is False


def test_optional_non_result_routes_exclude_none_but_result_does_not() -> None:
    routes = {route.name: route for route in journey_routes.router.routes}

    for route_name in (
        "create_document",
        "get_document_status",
        "reconcile_operation",
    ):
        assert routes[route_name].response_model_exclude_none is True
    assert routes["get_result"].response_model_exclude_none is False
