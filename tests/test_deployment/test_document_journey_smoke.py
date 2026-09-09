"""Hermetic HTTP smoke contracts; all identities and document data are synthetic."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import socket
import ssl
from types import SimpleNamespace

import jsonschema
import pytest

from tooling import document_journey_smoke as subject


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = "scanalyze.document-journey.v1"
DOCUMENT_ID = "a" * 32
OTHER_DOCUMENT_ID = "b" * 32
CREATED_AT = "2026-01-01T00:00:00Z"
COMPLETED_AT = "2026-01-01T00:00:03Z"
NOW = datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
API_ORIGIN = "https://api.synthetic.example.com"
UPLOAD_HOST = "scanalyze-synthetic.s3.us-east-1.amazonaws.com"
UPLOAD_URL = f"https://{UPLOAD_HOST}/synthetic-only.pdf?opaque=synthetic-only"
BEARER = "synthetic-access-value-for-hermetic-tests"


def config_dict():
    return {
        "schema_version": 1,
        "environment": "dev",
        "processing_domain": "bank",
        "api_origin": API_ORIGIN,
        "upload_host": UPLOAD_HOST,
        "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "region": "us-east-1",
        "authorization_reference": "12345678-1234-4234-8234-123456789abc",
        "timeout_seconds": 60,
        "poll_interval_seconds": 1,
        "max_requests": 32,
    }


def durable():
    return {
        "schemaVersion": "scanalyze.document-create-result.v1",
        "contractVersion": CONTRACT,
        "operation": "documents.create",
        "documentId": DOCUMENT_ID,
        "status": "UPLOAD_PENDING",
        "contentType": "application/pdf",
        "createdAt": CREATED_AT,
    }


def created():
    return {
        "schemaVersion": "scanalyze.operation-response.v1",
        "contractVersion": CONTRACT,
        "replayed": False,
        "durableResponse": durable(),
        "uploadCapability": {
            "method": "PUT",
            "url": UPLOAD_URL,
            "expiresAt": "2026-01-01T00:15:00Z",
            "requiredHeaders": {"Content-Type": "application/pdf"},
        },
    }


def submitted():
    return {
        "schemaVersion": "scanalyze.document-submit.v1",
        "contractVersion": CONTRACT,
        "documentId": DOCUMENT_ID,
        "stage": "ingest",
        "enqueued": True,
    }


def document_status(*, lifecycle="COMPLETED"):
    response = {
        "schemaVersion": "scanalyze.document-status.v1",
        "contractVersion": CONTRACT,
        "documentId": DOCUMENT_ID,
        "lifecycle": lifecycle,
        "currentStage": "TERMINAL",
        "stageState": "SUCCEEDED",
        "processingCondition": "NOT_APPLICABLE",
        "createdAt": CREATED_AT,
        "updatedAt": COMPLETED_AT,
        "terminalAt": COMPLETED_AT,
    }
    if lifecycle == "PROCESSING":
        response.update(currentStage="OCR", stageState="RUNNING", processingCondition="ACTIVE")
        response.pop("terminalAt")
    elif lifecycle == "FAILED":
        response.update(stageState="FAILED", failureDisposition="TERMINAL", safeFailureCode="OCR_FAILED")
    return response


def bank_result():
    return {
        "schemaVersion": "scanalyze.document-result.v1",
        "contractVersion": CONTRACT,
        "documentType": "bank_statement",
        "resultType": "bank_statement",
        "documentId": DOCUMENT_ID,
        "resultId": f"result_{DOCUMENT_ID}_v1",
        "resultVersion": "1.0",
        "provenance": {
            "processor": "bank-extract",
            "producerSchemaVersion": "1.0",
            "promptVersion": "1.0.0",
            "generatedAt": COMPLETED_AT,
        },
        "data": {
            "bank": {"name": "Scanalyze Synthetic Bank"},
            "account": {"holder": "SYNTHETIC TEST ONLY", "numberMasked": None,
                        "clabeMasked": None, "currency": "MXN"},
            "statement": {"periodStart": "2026-01-01", "periodEnd": "2026-01-31"},
            "balances": {"opening": 0.0, "closing": 100.0, "totalCredits": 100.0, "totalDebits": 0.0},
            "transactions": [{"date": "2026-01-01", "description": "SYNTHETIC TEST ONLY",
                              "reference": "E2E-0001", "direction": "credit", "amount": 100.0,
                              "balanceAfter": 100.0, "category": "transferencia"}],
            "accountType": None,
            "bankCountry": "MX",
            "fees": None,
            "interestEarned": None,
            "interestCharged": None,
            "summaryText": None,
        },
        "warnings": [],
        "quality": {"overallConfidence": 99.0},
    }


def replayed():
    # A completed document legitimately replays its original UPLOAD_PENDING
    # durable response without an ephemeral upload capability.
    return {"schemaVersion": "scanalyze.operation-response.v1", "contractVersion": CONTRACT,
            "replayed": True, "durableResponse": durable()}


def response(body, status=200, *, headers=None):
    return subject.HttpResponse(
        status=status,
        headers=headers if headers is not None else {
            "Content-Type": "application/json",
            "X-Correlation-ID": "ref_" + "c" * 32,
        },
        body=json.dumps(body).encode("utf-8") if not isinstance(body, bytes) else body,
    )


def happy_responses():
    return [response(created(), 201), response(b"", headers={}), response(submitted(), 202),
            response(document_status()), response(bank_result()), response(replayed(), 201)]


class FakeClock:
    def __init__(self):
        self.elapsed = 0.0
        self.delays = []

    def __call__(self):
        return self.elapsed

    def sleep(self, seconds):
        assert seconds >= 0
        self.delays.append(seconds)
        self.elapsed += seconds


class FakeTransport:
    def __init__(self, responses=None, *, repeat=None):
        self.responses = list(happy_responses() if responses is None else responses)
        self.repeat = repeat
        self.calls = []

    def request(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": body, "timeout": timeout})
        if self.responses:
            item = self.responses.pop(0)
        else:
            assert self.repeat is not None, "Unexpected extra synthetic HTTP request"
            item = self.repeat
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Real networking is outside the hermetic smoke tests")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def run(transport=None, *, options=None, progress=None, recovery=None, clock=None):
    transport = transport if transport is not None else FakeTransport()
    clock = clock if clock is not None else FakeClock()
    return subject.run_smoke(
        subject.SmokeConfig.from_dict(options if options is not None else config_dict()),
        BEARER,
        transport,
        on_progress=progress if progress is not None else lambda _event: None,
        on_recovery=recovery if recovery is not None else lambda _event: None,
        clock=clock,
        sleep=clock.sleep,
        utcnow=lambda: NOW,
    )


def assert_safe_failure(transport, *, options=None, progress=None, recovery=None, clock=None):
    with pytest.raises(subject.SmokeError) as failure:
        run(transport, options=options, progress=progress, recovery=recovery, clock=clock)
    assert re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", failure.value.code)
    assert str(failure.value) == failure.value.code
    assert BEARER not in str(failure.value)
    assert UPLOAD_URL not in str(failure.value)
    return failure.value.code


def test_synthetic_responses_match_authoritative_schemas():
    contract = json.loads((ROOT / "schemas/scanalyze-document-journey.openapi.v1.json").read_text())
    for name, value in (("DocumentCreateResponse", created()), ("DocumentCreateResponse", replayed()),
                        ("SubmitDocumentResponse", submitted()), ("DocumentStatusResponse", document_status()),
                        ("DocumentStatusResponse", document_status(lifecycle="PROCESSING")),
                        ("DocumentStatusResponse", document_status(lifecycle="FAILED"))):
        jsonschema.Draft202012Validator(
            {**contract, "$ref": f"#/components/schemas/{name}"},
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)
    result_schema = json.loads((ROOT / "schemas/scanalyze-document-journey-result.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(result_schema, format_checker=jsonschema.FormatChecker()).validate(bank_result())


def test_synthetic_pdf_is_deterministic_and_contains_only_test_markers():
    pdf = subject.synthetic_pdf()
    assert isinstance(pdf, bytes)
    assert pdf == subject.synthetic_pdf()
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"SYNTHETIC TEST ONLY" in pdf
    assert b"Scanalyze Synthetic Bank" in pdf
    assert b"E2E-0001" in pdf


def test_complete_http_journey_and_replay_are_bound_without_credential_forwarding(capsys):
    transport = FakeTransport()
    events = []

    result = run(transport, progress=lambda event: events.append(deepcopy(event)))

    assert result["status"] == "APPLICATION_SMOKE_PASSED"
    assert result["production_authorized"] is False
    assert result["requests"] == len(transport.calls) == 6
    assert result["completed_steps"] == ["CREATE", "UPLOAD", "SUBMIT", "STATUS", "RESULT", "REPLAY"]
    assert isinstance(result["elapsed_milliseconds"], int)
    assert result["elapsed_milliseconds"] >= 0
    assert result["document_id_sha256"].removeprefix("sha256:") == hashlib.sha256(DOCUMENT_ID.encode()).hexdigest()
    assert result["pdf_sha256"].removeprefix("sha256:") == hashlib.sha256(subject.synthetic_pdf()).hexdigest()
    assert [(call["method"], call["url"]) for call in transport.calls] == [
        ("POST", f"{API_ORIGIN}/api/v2/documents"), ("PUT", UPLOAD_URL),
        ("POST", f"{API_ORIGIN}/api/v2/documents/{DOCUMENT_ID}/submit"),
        ("GET", f"{API_ORIGIN}/api/v2/documents/{DOCUMENT_ID}"),
        ("GET", f"{API_ORIGIN}/api/v2/documents/{DOCUMENT_ID}/result"),
        ("POST", f"{API_ORIGIN}/api/v2/documents"),
    ]
    first, upload, submit, _, _, replay = transport.calls
    api_headers = [{key.lower(): value for key, value in call["headers"].items()}
                   for call in transport.calls if call is not upload]
    for headers in api_headers:
        assert headers["authorization"] == f"Bearer {BEARER}"
        assert headers["x-scanalyze-contract-version"] == CONTRACT
        assert "x-tenant-id" not in headers
    first_headers = {key.lower(): value for key, value in first["headers"].items()}
    replay_headers = {key.lower(): value for key, value in replay["headers"].items()}
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        first_headers["idempotency-key"])
    assert replay_headers["idempotency-key"] == first_headers["idempotency-key"]
    assert json.loads(first["body"]) == json.loads(replay["body"])
    assert json.loads(first["body"])["contentLength"] == len(subject.synthetic_pdf())
    assert json.loads(submit["body"]) == {"stage": "ingest"}
    upload_headers = {key.lower(): value for key, value in upload["headers"].items()}
    assert upload_headers["content-type"] == "application/pdf"
    assert not set(upload_headers) & {"authorization", "cookie", "x-scanalyze-contract-version",
                                      "idempotency-key", "x-correlation-id", "x-tenant-id"}
    assert upload["body"] == subject.synthetic_pdf()
    assert all(0 < call["timeout"] <= 60 for call in transport.calls)
    assert events
    public = json.dumps({"result": result, "events": events})
    for private in (BEARER, UPLOAD_URL, DOCUMENT_ID, "SYNTHETIC TEST ONLY", "E2E-0001"):
        assert private not in public
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_processing_polls_are_bounded_and_do_not_resubmit():
    responses = happy_responses()
    responses.insert(3, response(document_status(lifecycle="PROCESSING")))
    transport, clock = FakeTransport(responses), FakeClock()

    result = run(transport, clock=clock)

    assert result["requests"] == 7
    assert clock.delays
    assert len([call for call in transport.calls if call["url"].endswith("/submit")]) == 1


def test_failed_document_stops_before_result_and_replay():
    responses = happy_responses()
    responses[3] = response(document_status(lifecycle="FAILED"))
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 4


def test_pending_document_exhausts_deadline_without_more_mutations():
    options = {**config_dict(), "timeout_seconds": 30, "poll_interval_seconds": 30}
    transport = FakeTransport(happy_responses()[:3], repeat=response(document_status(lifecycle="PROCESSING")))
    clock = FakeClock()
    assert_safe_failure(transport, options=options, clock=clock)
    assert len(transport.calls) <= 5
    assert clock.elapsed >= 30


def test_request_budget_stops_before_the_seventh_request():
    options = {**config_dict(), "max_requests": 6}
    transport = FakeTransport(happy_responses()[:3], repeat=response(document_status(lifecycle="PROCESSING")))
    assert_safe_failure(transport, options=options)
    assert len(transport.calls) <= 6


@pytest.mark.parametrize("index", [0, 2, 3, 4, 5])
def test_wrong_contract_version_stops_at_its_response(index):
    responses = happy_responses()
    body = json.loads(responses[index].body)
    body["contractVersion"] = "scanalyze.unsupported.v999"
    responses[index] = response(body, responses[index].status)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == index + 1


@pytest.mark.parametrize("index", [2, 3, 4])
def test_document_identity_mismatch_stops_without_replay(index):
    responses = happy_responses()
    body = json.loads(responses[index].body)
    body["documentId"] = OTHER_DOCUMENT_ID
    if index == 4:
        body["resultId"] = f"result_{OTHER_DOCUMENT_ID}_v1"
    responses[index] = response(body, responses[index].status)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == index + 1


@pytest.mark.parametrize("field,value", [("documentId", OTHER_DOCUMENT_ID),
                                         ("createdAt", "2026-01-01T00:00:01Z"),
                                         ("contentType", "image/png")])
def test_replay_requires_the_same_durable_response(field, value):
    responses = happy_responses()
    body = replayed()
    body["durableResponse"][field] = value
    responses[-1] = response(body, 201)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 6


@pytest.mark.parametrize("url", [
    "https://untrusted.synthetic.example.com/upload", f"http://{UPLOAD_HOST}/upload",
    f"https://{UPLOAD_HOST}.untrusted.example.com/upload", f"https://{UPLOAD_HOST}@untrusted.example.com/upload",
    f"https://{UPLOAD_HOST}:444/upload", f"https://{UPLOAD_HOST}/upload#fragment",
])
def test_upload_url_outside_exact_target_is_never_contacted(url):
    responses = happy_responses()
    body = created()
    body["uploadCapability"]["url"] = url
    responses[0] = response(body, 201)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 1


def test_expired_upload_capability_is_never_used():
    responses = happy_responses()
    body = created()
    body["uploadCapability"]["expiresAt"] = "2025-12-31T23:59:59Z"
    responses[0] = response(body, 201)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("field,value", [("method", "POST"),
                                         ("requiredHeaders", {"Content-Type": "image/png"}),
                                         ("requiredHeaders", {"Content-Type": "application/pdf", "Authorization": "synthetic"})])
def test_unexpected_upload_instructions_fail_before_transfer(field, value):
    responses = happy_responses()
    body = created()
    body["uploadCapability"][field] = value
    responses[0] = response(body, 201)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("index", range(6))
def test_http_errors_are_not_retried_even_if_the_envelope_is_retryable(index):
    responses = happy_responses()
    responses[index] = response({"schemaVersion": "scanalyze.error.v1", "code": "RATE_LIMITED",
                                 "message": "The request rate is limited.", "correlationId": "ref_" + "c" * 32,
                                 "retryClass": "RETRYABLE_WITH_BACKOFF", "details": {"retryAfterSeconds": 1}},
                                429, headers={"Content-Type": "application/json", "Retry-After": "1"})
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == index + 1


@pytest.mark.parametrize("body", [b"not-json", b"\xff", b"[]", b'{"schemaVersion":1,"schemaVersion":2}'])
def test_invalid_response_json_is_sanitized_without_retries(body):
    transport = FakeTransport([response(body, 201)])
    assert_safe_failure(transport)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("path,value", [
    (("data", "bank", "name"), "Different Synthetic Bank"),
    (("data", "account", "currency"), "USD"),
    (("data", "statement", "periodStart"), "2025-12-31"),
    (("data", "statement", "periodEnd"), "2026-01-30"),
    (("data", "statement"), {"periodStart": "2026-01-31", "periodEnd": "2026-01-01"}),
    (("data", "balances", "opening"), 1.0), (("data", "balances", "closing"), 101.0),
    (("data", "transactions", 0, "amount"), 99.0), (("data", "transactions", 0, "balanceAfter"), 99.0),
    (("data", "transactions", 0, "direction"), "debit"),
    (("data", "transactions", 0, "date"), "2026-01-02"),
    (("data", "transactions", 0, "reference"), "E2E-0002"),
    (("quality", "overallConfidence"), 89.99), (("warnings",), [{"code": "LOW_CONFIDENCE"}]),
    (("data", "transactions"), []),
])
def test_schema_valid_but_wrong_synthetic_result_cannot_pass(path, value):
    responses = happy_responses()
    body = bank_result()
    container = body
    for key in path[:-1]:
        container = container[key]
    container[path[-1]] = value
    responses[4] = response(body)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 5


def test_progress_failure_before_first_request_never_reaches_transport():
    transport = FakeTransport()

    def failing_progress(_event):
        raise RuntimeError(f"synthetic-private-diagnostic {UPLOAD_URL} {BEARER}")

    assert_safe_failure(transport, progress=failing_progress)
    assert transport.calls == []


def test_progress_persistence_failure_after_create_prevents_upload():
    transport = FakeTransport()

    def failing_progress(event):
        if event["stage"] == "CREATE" and event["status"] == "STEP_PASSED":
            raise RuntimeError("synthetic-private-progress-diagnostic")

    assert_safe_failure(transport, progress=failing_progress)
    assert len(transport.calls) == 1


def test_staging_target_has_the_same_nonproduction_boundary():
    result = run(options={**config_dict(), "environment": "staging"})
    assert result["status"] == "APPLICATION_SMOKE_PASSED"
    assert result["production_authorized"] is False


def test_recovery_events_bind_prepared_request_and_created_id_before_http_effects():
    transport = FakeTransport()
    recovery_events = []
    progress_events = []

    def record_recovery(event):
        recovery_events.append((len(transport.calls), deepcopy(event)))

    result = run(transport, recovery=record_recovery,
                 progress=lambda event: progress_events.append(deepcopy(event)))

    assert len(recovery_events) == 2
    before_create, prepared = recovery_events[0]
    before_upload, materialized = recovery_events[1]
    headers = {key.lower(): value for key, value in transport.calls[0]["headers"].items()}
    assert before_create == 0
    assert prepared == {
        "event": "CREATE_PREPARED",
        "idempotency_key": headers["idempotency-key"],
        "request_sha256": "sha256:" + hashlib.sha256(transport.calls[0]["body"]).hexdigest(),
    }
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        prepared["idempotency_key"])
    assert before_upload == 1
    assert materialized == {"event": "DOCUMENT_CREATED", "document_id": DOCUMENT_ID}
    public = json.dumps({"result": result, "progress": progress_events})
    for private in (prepared["idempotency_key"], prepared["request_sha256"], DOCUMENT_ID):
        assert private not in public
    assert "CREATE_PREPARED" not in public
    assert "DOCUMENT_CREATED" not in public


@pytest.mark.parametrize("event_name,expected_requests", [("CREATE_PREPARED", 0), ("DOCUMENT_CREATED", 1)])
def test_recovery_persistence_failure_stops_before_next_http_effect(event_name, expected_requests):
    transport = FakeTransport()
    observed = []

    def failing_recovery(event):
        observed.append(deepcopy(event))
        if event["event"] == event_name:
            raise RuntimeError("synthetic-private-recovery-diagnostic " + json.dumps(event))

    assert_safe_failure(transport, recovery=failing_recovery)
    assert len(transport.calls) == expected_requests
    assert observed[-1]["event"] == event_name


def test_absent_recovery_callback_blocks_before_contract_pdf_or_http(monkeypatch):
    transport = FakeTransport()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Recovery admission must precede local preparation and HTTP")

    monkeypatch.setattr(subject, "_Contracts", forbidden)
    monkeypatch.setattr(subject, "synthetic_pdf", forbidden)

    with pytest.raises(subject.SmokeError, match="^RECOVERY_JOURNAL_REQUIRED$"):
        subject.run_smoke(subject.SmokeConfig.from_dict(config_dict()), BEARER, transport)

    assert transport.calls == []


@pytest.mark.parametrize("callback", [None, False, 0, "not-callable", {}, []])
def test_noncallable_recovery_callback_blocks_before_contract_pdf_or_http(monkeypatch, callback):
    transport = FakeTransport()

    def forbidden(*_args, **_kwargs):
        pytest.fail("Recovery admission must precede local preparation and HTTP")

    monkeypatch.setattr(subject, "_Contracts", forbidden)
    monkeypatch.setattr(subject, "synthetic_pdf", forbidden)

    with pytest.raises(subject.SmokeError, match="^RECOVERY_JOURNAL_REQUIRED$"):
        subject.run_smoke(subject.SmokeConfig.from_dict(config_dict()), BEARER, transport,
                          on_recovery=callback)

    assert transport.calls == []


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("environment", "production"),
    ("processing_domain", "platform"), ("region", "us-west-2"),
    ("api_origin", "http://api.synthetic.example.com"), ("api_origin", API_ORIGIN + "/api"),
    ("api_origin", API_ORIGIN + "?query=synthetic"), ("api_origin", API_ORIGIN + "#fragment"),
    ("api_origin", API_ORIGIN + ":444"),
    ("upload_host", "untrusted.synthetic.example.com"),
    ("deployment_id", "invented"), ("authorization_reference", "not-a-uuid"),
    ("timeout_seconds", True), ("timeout_seconds", 29), ("timeout_seconds", 601),
    ("poll_interval_seconds", True), ("poll_interval_seconds", 0), ("poll_interval_seconds", 31),
    ("max_requests", True), ("max_requests", 5), ("max_requests", 257),
])
def test_invalid_configuration_fails_before_network(field, value):
    config = config_dict()
    config[field] = value
    transport = FakeTransport()
    assert_safe_failure(transport, options=config)
    assert transport.calls == []


@pytest.mark.parametrize("field", list(config_dict()))
def test_missing_configuration_field_has_no_default(field):
    config = config_dict()
    config.pop(field)
    with pytest.raises(subject.SmokeError):
        subject.SmokeConfig.from_dict(config)


def test_unknown_configuration_field_is_not_ignored():
    config = {**config_dict(), "production_authorized": True}
    with pytest.raises(subject.SmokeError):
        subject.SmokeConfig.from_dict(config)


@pytest.mark.parametrize("index", [0, 2, 3, 4, 5])
def test_api_success_with_wrong_media_type_is_not_accepted(index):
    responses = happy_responses()
    responses[index] = response(responses[index].body, responses[index].status,
                                headers={"Content-Type": "text/html"})
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == index + 1


def test_transport_exception_is_sanitized_and_never_retried():
    transport = FakeTransport([RuntimeError(f"synthetic-private-diagnostic {UPLOAD_URL} {BEARER}")])
    assert_safe_failure(transport)
    assert len(transport.calls) == 1


def test_status_created_at_must_match_durable_creation():
    responses = happy_responses()
    body = document_status()
    body["createdAt"] = "2026-01-01T00:00:01Z"
    responses[3] = response(body)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 4


def test_status_timestamp_cannot_move_backwards_between_polls():
    responses = happy_responses()
    processing = document_status(lifecycle="PROCESSING")
    processing["updatedAt"] = "2026-01-01T00:00:05Z"
    responses.insert(3, response(processing))
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == 5


@pytest.mark.parametrize("stage", ["create", "status", "result"])
def test_future_response_timestamps_are_not_live_evidence(stage):
    responses = happy_responses()
    index = {"create": 0, "status": 3, "result": 4}[stage]
    body = json.loads(responses[index].body)
    if stage == "create":
        body["durableResponse"]["createdAt"] = "2026-01-02T00:00:00Z"
    elif stage == "status":
        body["updatedAt"] = "2026-01-02T00:00:00Z"
    else:
        body["provenance"]["generatedAt"] = "2026-01-02T00:00:00Z"
    responses[index] = response(body, responses[index].status)
    transport = FakeTransport(responses)
    assert_safe_failure(transport)
    assert len(transport.calls) == index + 1


_TRANSPORT_ENVIRONMENT = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
)


@pytest.fixture
def clean_transport_environment(monkeypatch):
    for name in _TRANSPORT_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


def dns_answer(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))


@pytest.mark.parametrize("name", _TRANSPORT_ENVIRONMENT)
def test_https_transport_rejects_proxy_and_alternate_ca_before_dns(monkeypatch, clean_transport_environment, name):
    monkeypatch.setenv(name, "synthetic-untrusted-override")
    calls = []
    monkeypatch.setattr(subject.socket, "getaddrinfo", lambda *_args, **_kwargs: calls.append("dns"))

    with pytest.raises(subject.SmokeError, match="^TRANSPORT_ENVIRONMENT_UNSAFE$"):
        subject.HttpsTransport().request("GET", API_ORIGIN, {}, None, 1)

    assert calls == []


@pytest.mark.parametrize("addresses", [
    [], ["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["100.64.0.1"],
    ["::1"], ["fd00::1"], ["8.8.8.8", "127.0.0.1"],
])
def test_https_transport_rejects_any_nonpublic_dns_answer(monkeypatch, clean_transport_environment, addresses):
    monkeypatch.setattr(subject.socket, "getaddrinfo",
                        lambda *_args, **_kwargs: [dns_answer(address) for address in addresses])
    connections = []
    monkeypatch.setattr(subject, "_PinnedConnection", lambda *_args, **_kwargs: connections.append("connect"))

    with pytest.raises(subject.SmokeError, match="^ADDRESS_NOT_ALLOWED$"):
        subject.HttpsTransport().request("GET", API_ORIGIN, {}, None, 1)

    assert connections == []


class FakeWireResponse:
    def __init__(self, *, status=200, payload=b"{}", encoding="identity", failure=None):
        self.status = status
        self.payload = payload
        self.encoding = encoding
        self.failure = failure
        self.read_limits = []
        self.offset = 0

    def getheader(self, name, default=None):
        return {"Content-Encoding": self.encoding, "Content-Type": "application/json",
                "Location": "https://untrusted.synthetic.example.com"}.get(name, default)

    def read1(self, maximum):
        self.read_limits.append(maximum)
        if self.failure == "read":
            raise OSError("synthetic-private-wire-diagnostic")
        chunk = self.payload[self.offset:self.offset + maximum]
        self.offset += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, hostname, address, timeout, *, wire, failure=None):
        self.hostname = hostname
        self.address = address
        self.timeout = timeout
        self.wire = wire
        self.failure = failure
        self.calls = []
        self.closed = False
        self.socket_timeouts = []
        self.sock = SimpleNamespace(settimeout=self.socket_timeouts.append)

    def request(self, method, path, *, body, headers):
        self.calls.append((method, path, body, headers))
        if self.failure == "request":
            raise OSError("synthetic-private-wire-diagnostic")

    def getresponse(self):
        if self.failure == "getresponse":
            raise OSError("synthetic-private-wire-diagnostic")
        return self.wire

    def close(self):
        self.closed = True
        if self.failure == "close":
            raise OSError("synthetic-private-wire-diagnostic")


def fake_wire_transport(monkeypatch, *, wire=None, failure=None):
    wire = wire if wire is not None else FakeWireResponse()
    dns_calls = []
    connections = []

    def dns(hostname, port, **kwargs):
        dns_calls.append((hostname, port, kwargs))
        return [dns_answer("8.8.8.8")]

    def connection(hostname, address, timeout):
        created_connection = FakeConnection(hostname, address, timeout, wire=wire, failure=failure)
        connections.append(created_connection)
        return created_connection

    monkeypatch.setattr(subject.socket, "getaddrinfo", dns)
    monkeypatch.setattr(subject, "_PinnedConnection", connection)
    return subject.HttpsTransport(), dns_calls, connections


def test_https_transport_pins_validated_address_and_preserves_signed_path(monkeypatch, clean_transport_environment):
    transport, dns_calls, connections = fake_wire_transport(monkeypatch)

    result = transport.request("PUT", UPLOAD_URL, {"Content-Type": "application/pdf"}, b"synthetic", 5)

    assert result.status == 200
    assert len(dns_calls) == len(connections) == 1
    connection = connections[0]
    assert (connection.hostname, connection.address) == (UPLOAD_HOST, "8.8.8.8")
    assert 0 < connection.timeout <= 5
    assert connection.calls == [("PUT", "/synthetic-only.pdf?opaque=synthetic-only", b"synthetic",
                                  {"Content-Type": "application/pdf"})]
    assert connection.wire.read_limits and max(connection.wire.read_limits) <= 65_536
    assert connection.socket_timeouts and all(0 < value <= 5 for value in connection.socket_timeouts)
    assert connection.closed is True


def test_https_transport_never_follows_redirect(monkeypatch, clean_transport_environment):
    transport, dns_calls, connections = fake_wire_transport(monkeypatch, wire=FakeWireResponse(status=302))

    result = transport.request("POST", API_ORIGIN + "/api/v2/documents", {}, b"{}", 5)

    assert result.status == 302
    assert len(dns_calls) == len(connections) == 1
    assert len(connections[0].calls) == 1
    assert connections[0].closed is True


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate"])
def test_https_transport_rejects_encoded_bodies_without_reading_them(monkeypatch, clean_transport_environment, encoding):
    wire = FakeWireResponse(encoding=encoding)
    transport, _, connections = fake_wire_transport(monkeypatch, wire=wire)

    with pytest.raises(subject.SmokeError, match="^RESPONSE_ENCODING_UNSUPPORTED$"):
        transport.request("GET", API_ORIGIN, {}, None, 5)

    assert wire.read_limits == []
    assert connections[0].closed is True


def test_https_transport_bounds_response_body(monkeypatch, clean_transport_environment):
    wire = FakeWireResponse(payload=b"x" * (subject.MAX_BODY + 1))
    transport, _, connections = fake_wire_transport(monkeypatch, wire=wire)

    with pytest.raises(subject.SmokeError, match="^RESPONSE_TOO_LARGE$"):
        transport.request("GET", API_ORIGIN, {}, None, 5)

    assert wire.offset == subject.MAX_BODY + 1
    assert max(wire.read_limits) <= 65_536
    assert connections[0].closed is True


@pytest.mark.parametrize("phase", ["request", "getresponse", "read", "close"])
def test_https_transport_failure_never_exposes_wire_diagnostics(monkeypatch, clean_transport_environment, phase):
    wire = FakeWireResponse(failure=phase)
    transport, _, connections = fake_wire_transport(monkeypatch, wire=wire, failure=phase)

    with pytest.raises(subject.SmokeError) as failure:
        transport.request("POST", API_ORIGIN, {}, b"{}", 5)

    assert str(failure.value) == failure.value.code
    assert "synthetic-private" not in str(failure.value)
    assert connections[0].closed is True


def test_pinned_connection_uses_default_tls_context_and_original_sni(monkeypatch):
    tls_calls = []
    tcp_calls = []
    raw_socket = SimpleNamespace(close=lambda: None)
    wrapped_socket = object()

    def wrap(sock, *, server_hostname):
        tls_calls.append((sock, server_hostname))
        return wrapped_socket

    context = SimpleNamespace(post_handshake_auth=None, check_hostname=True,
                              verify_mode=ssl.CERT_REQUIRED, wrap_socket=wrap)
    default_context_calls = []
    monkeypatch.setattr(subject.ssl, "create_default_context",
                        lambda: default_context_calls.append(True) or context)

    def tcp(address, *, timeout):
        tcp_calls.append((address, timeout))
        return raw_socket

    monkeypatch.setattr(subject.socket, "create_connection", tcp)
    connection = subject._PinnedConnection("api.synthetic.example.com", "8.8.8.8", 5)

    connection.connect()

    assert default_context_calls == [True]
    assert tcp_calls == [(("8.8.8.8", 443), 5)]
    assert tls_calls == [(raw_socket, "api.synthetic.example.com")]
    assert connection.sock is wrapped_socket


def test_dns_resolution_consumes_transport_deadline(monkeypatch, clean_transport_environment):
    clock = FakeClock()
    monkeypatch.setattr(subject.time, "monotonic", clock)
    connections = []

    def slow_dns(*_args, **_kwargs):
        clock.elapsed = 6
        return [dns_answer("8.8.8.8")]

    monkeypatch.setattr(subject.socket, "getaddrinfo", slow_dns)
    monkeypatch.setattr(subject, "_PinnedConnection", lambda *_args, **_kwargs: connections.append(True))

    with pytest.raises(subject.SmokeError, match="^TIME_BUDGET_EXHAUSTED$"):
        subject.HttpsTransport().request("GET", API_ORIGIN, {}, None, 5)

    assert connections == []


def test_slow_response_chunks_cannot_reset_total_transport_deadline(monkeypatch, clean_transport_environment):
    clock = FakeClock()
    monkeypatch.setattr(subject.time, "monotonic", clock)
    wire = FakeWireResponse(payload=b"{}")
    original_read = wire.read1

    def slow_read(maximum):
        clock.elapsed += 6
        return original_read(maximum)

    wire.read1 = slow_read
    transport, _, connections = fake_wire_transport(monkeypatch, wire=wire)

    with pytest.raises(subject.SmokeError, match="^TIME_BUDGET_EXHAUSTED$"):
        transport.request("GET", API_ORIGIN, {}, None, 5)

    assert len(wire.read_limits) == 1
    assert connections[0].closed is True
