"""Direct runtime-contract tests for GUG-354's fail-closed adapters."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app import journey_contract as contract
from app.journey_contract import (
    CONTRACT_VERSION,
    BatchCreateRequest,
    DocumentCreateRequest,
    DocumentCreateResponse,
    DocumentLifecycle,
    DocumentStatusResponse,
    ErrorCode,
    ErrorDetails,
    FailureDisposition,
    JourneyContractError,
    LedgerState,
    MalformedInternalResult,
    OperationKind,
    PipelineStage,
    ProcessingCondition,
    ReconciliationFailureCode,
    ReconciliationResponse,
    SafeFailureCode,
    StageState,
    SubmitDocumentRequest,
    UnsupportedInternalState,
    adapt_internal_document_status,
    canonical_request_digest,
    parse_strict_request,
    project_bank_statement_result,
    public_error,
    validate_lifecycle_transition,
)
from test_gug354_journey_service import _bank_artifact


DOCUMENT_ID = "a" * 32
NOW = datetime(2026, 8, 8, 18, 2, tzinfo=timezone.utc)
CREATED = datetime(2026, 8, 8, 18, 0, tzinfo=timezone.utc)
UPDATED = datetime(2026, 8, 8, 18, 1, tzinfo=timezone.utc)


def _record(status: str, **updates: object) -> dict[str, object]:
    record: dict[str, object] = {
        "documentId": DOCUMENT_ID,
        "status": status,
        "createdAt": CREATED.isoformat(),
        "updatedAt": UPDATED.isoformat(),
        "stages": {},
    }
    record.update(updates)
    return record


def _terminal_record(status: str) -> dict[str, object]:
    validation = "PASS" if status == "COMPLETED" else "FAIL"
    return _record(
        status,
        completedAt=UPDATED.isoformat(),
        validation={"status": validation},
        stages={
            "persist": {
                "status": "DONE",
                "finalStatus": status,
                "completedAt": UPDATED.isoformat(),
            }
        },
    )


@pytest.mark.parametrize(
    "raw,model",
    [
        (b'{"content_type":"application/pdf"}', DocumentCreateRequest),
        (b'{"contentType":"application/pdf","contentLength":1.0}', DocumentCreateRequest),
        (b'{"stage":null}', SubmitDocumentRequest),
        (b'{"stage":"ingest","stage":"ingest"}', SubmitDocumentRequest),
    ],
)
def test_request_wire_rejects_alias_coercion_null_and_duplicate_keys(
    raw: bytes, model: type[object]
) -> None:
    with pytest.raises((JourneyContractError, ValidationError)):
        parse_strict_request(raw, model)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw",
    [
        '{"contentType":"application/pdf"}'.encode("utf-16"),
        '{"contentType":"application/pdf"}'.encode("utf-32"),
        b"\xef\xbb\xbf{\"contentType\":\"application/pdf\"}",
    ],
)
def test_request_wire_accepts_only_bomless_utf8_json(raw: bytes) -> None:
    with pytest.raises(JourneyContractError):
        parse_strict_request(raw, DocumentCreateRequest)


def test_request_digest_binds_exact_operation_and_semantics() -> None:
    request = DocumentCreateRequest(contentType="application/pdf")
    first = canonical_request_digest(OperationKind.DOCUMENT_CREATE, request)
    assert first == canonical_request_digest("documents.create", request)
    with pytest.raises(JourneyContractError):
        canonical_request_digest(OperationKind.BATCH_CREATE, request)
    assert first != canonical_request_digest(
        OperationKind.DOCUMENT_CREATE,
        DocumentCreateRequest(contentType="image/png"),
    )


def _document_create_response(
    *, replayed: bool, include_capability: bool
) -> DocumentCreateResponse:
    payload: dict[str, object] = {
        "replayed": replayed,
        "durableResponse": {
            "schemaVersion": "scanalyze.document-create-result.v1",
            "contractVersion": CONTRACT_VERSION,
            "operation": OperationKind.DOCUMENT_CREATE,
            "documentId": DOCUMENT_ID,
            "status": "UPLOAD_PENDING",
            "contentType": "application/pdf",
            "createdAt": CREATED,
        },
    }
    if include_capability:
        payload["uploadCapability"] = {
            "method": "PUT",
            "url": "https://upload.invalid/document",
            "expiresAt": UPDATED,
            "requiredHeaders": {"Content-Type": "application/pdf"},
        }
    return DocumentCreateResponse(**payload)


def test_document_create_capability_is_required_only_for_first_response() -> None:
    first = _document_create_response(replayed=False, include_capability=True)
    replay_with_capability = _document_create_response(
        replayed=True, include_capability=True
    )
    replay_without_capability = _document_create_response(
        replayed=True, include_capability=False
    )

    assert first.upload_capability is not None
    assert replay_with_capability.upload_capability is not None
    assert replay_without_capability.upload_capability is None
    with pytest.raises(ValidationError):
        _document_create_response(replayed=False, include_capability=False)


@pytest.mark.parametrize(
    "status,stages,updates,expected_stage,expected_state",
    [
        ("CREATED", {}, {}, PipelineStage.INGEST, StageState.PENDING),
        (
            "OCR",
            {"ocr": {"status": "IN_PROGRESS"}},
            {},
            PipelineStage.OCR,
            StageState.RUNNING,
        ),
        (
            "OCR_COMPLETED",
            {
                "ocr": {"status": "COMPLETED"},
                "classify": {"status": "ENQUEUED"},
            },
            {},
            PipelineStage.OCR,
            StageState.SUCCEEDED,
        ),
        (
            "CLASSIFY_PENDING",
            {"classify": {"status": "PENDING_HANDOFF"}},
            {},
            PipelineStage.CLASSIFY,
            StageState.PENDING,
        ),
        (
            "CLASSIFY_COMPLETED",
            {"classify": {"status": "COMPLETED"}},
            {},
            PipelineStage.CLASSIFY,
            StageState.SUCCEEDED,
        ),
        (
            "BANK_EXTRACTING",
            {"bank_extract": {"status": "WRITING"}},
            {"processing_domain": "bank", "documentRoute": "bank"},
            PipelineStage.BANK_EXTRACT,
            StageState.RUNNING,
        ),
        (
            "BANK_EXTRACTED",
            {"bank_extract": {"status": "COMPLETED"}},
            {"processing_domain": "bank", "documentRoute": "bank"},
            PipelineStage.BANK_EXTRACT,
            StageState.SUCCEEDED,
        ),
        (
            "PERSONAL_EXTRACTING",
            {"personal_extract": {"status": "WRITING"}},
            {"processing_domain": "personal", "documentRoute": "personal"},
            PipelineStage.PERSONAL_EXTRACT,
            StageState.RUNNING,
        ),
        (
            "PERSONAL_EXTRACTED",
            {"personal_extract": {"status": "COMPLETED"}},
            {"processing_domain": "personal", "documentRoute": "personal"},
            PipelineStage.PERSONAL_EXTRACT,
            StageState.SUCCEEDED,
        ),
    ],
)
def test_every_reviewed_nonterminal_internal_status_projects(
    status: str,
    stages: dict[str, object],
    updates: dict[str, object],
    expected_stage: PipelineStage,
    expected_state: StageState,
) -> None:
    projected = adapt_internal_document_status(
        _record(status, stages=stages, **updates), now=NOW
    )
    assert projected.lifecycle in {
        DocumentLifecycle.UPLOAD_PENDING,
        DocumentLifecycle.PROCESSING,
    }
    assert projected.current_stage is expected_stage
    assert projected.stage_state is expected_state
    assert projected.processing_condition is ProcessingCondition.ACTIVE


@pytest.mark.parametrize(
    "status",
    [
        "RECEIVED",
        "UPLOADED",
        "INGEST",
        "OCR_PROCESSING",
        "CLASSIFY_PROCESSING",
        "GOV_EXTRACTING",
        "GOV_EXTRACTED",
        "VALIDATING",
        "VALIDATED",
        "PERSISTING",
        "UNKNOWN_OR_QUARANTINED",
    ],
)
def test_unproduced_internal_document_statuses_fail_closed(status: str) -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(_record(status), now=NOW)


def test_submitted_variants_and_ocr_failure_are_explicit() -> None:
    pending = adapt_internal_document_status(
        _record("SUBMITTED", stages={"ingest": {"status": "ENQUEUE_PENDING"}}),
        now=NOW,
    )
    assert pending.stage_state is StageState.PENDING

    failed = adapt_internal_document_status(
        _record("SUBMITTED", stages={"ingest": {"status": "ENQUEUE_FAILED"}}),
        now=NOW,
    )
    assert failed.failure_disposition is FailureDisposition.RETRYABLE
    assert failed.safe_failure_code is SafeFailureCode.ENQUEUE_FAILED
    assert failed.processing_condition is ProcessingCondition.NOT_APPLICABLE

    ocr_failed = adapt_internal_document_status(
        _record("OCR_FAILED", stages={"ocr": {"status": "IN_PROGRESS"}}),
        now=NOW,
    )
    assert ocr_failed.lifecycle is DocumentLifecycle.FAILED
    assert ocr_failed.safe_failure_code is SafeFailureCode.OCR_FAILED
    assert ocr_failed.terminal_at == UPDATED


def test_terminal_records_require_matching_persist_validation_and_timestamp() -> None:
    completed = adapt_internal_document_status(_terminal_record("COMPLETED"), now=NOW)
    failed = adapt_internal_document_status(_terminal_record("FAILED"), now=NOW)
    assert completed.lifecycle is DocumentLifecycle.COMPLETED
    assert failed.safe_failure_code is SafeFailureCode.DOCUMENT_PROCESSING_FAILED

    for mutation in ("missing-persist", "wrong-final", "missing-completed"):
        record = _terminal_record("COMPLETED")
        if mutation == "missing-persist":
            record["stages"] = {}
        elif mutation == "wrong-final":
            record["stages"]["persist"]["finalStatus"] = "FAILED"  # type: ignore[index]
        else:
            record.pop("completedAt")
        with pytest.raises(UnsupportedInternalState):
            adapt_internal_document_status(record, now=NOW)


@pytest.mark.parametrize("raw_state", ["PASS", "WARN", "COMPLETED"])
def test_persist_accepts_only_its_exact_done_state(raw_state: str) -> None:
    record = _terminal_record("COMPLETED")
    record["stages"]["persist"]["status"] = raw_state  # type: ignore[index]

    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(record, now=NOW)


@pytest.mark.parametrize(
    "stage_name,raw_state",
    [
        ("ocr", "DONE"),
        ("classify", "DONE"),
        ("validate", "COMPLETED"),
        ("notify", "COMPLETED"),
    ],
)
def test_raw_stage_states_are_validated_before_public_normalization(
    stage_name: str, raw_state: str
) -> None:
    record = _terminal_record("COMPLETED")
    record["stages"][stage_name] = {"status": raw_state}  # type: ignore[index]

    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(record, now=NOW)


def test_terminal_record_accepts_only_coherent_completed_stage_history() -> None:
    record = _terminal_record("COMPLETED")
    record.update(processing_domain="bank", documentRoute="bank")
    record["stages"].update(  # type: ignore[union-attr]
        {
            "ingest": {"status": "ENQUEUED"},
            "ocr": {"status": "COMPLETED"},
            "classify": {"status": "COMPLETED"},
            "bank_extract": {"status": "COMPLETED"},
            "validate": {"status": "DONE"},
            "notify": {"status": "DONE"},
        }
    )

    projected = adapt_internal_document_status(record, now=NOW)

    assert projected.lifecycle is DocumentLifecycle.COMPLETED
    assert projected.stage_state is StageState.SUCCEEDED


@pytest.mark.parametrize(
    "stage_name,raw_state",
    [
        ("ingest", "ENQUEUE_PENDING"),
        ("ocr", "IN_PROGRESS"),
        ("classify", "PENDING_HANDOFF"),
        ("bank_extract", "WRITING"),
        ("validate", "PROCESSING"),
    ],
)
def test_normal_terminal_record_rejects_pending_or_running_stage_history(
    stage_name: str, raw_state: str
) -> None:
    record = _terminal_record("COMPLETED")
    if stage_name == "bank_extract":
        record.update(processing_domain="bank", documentRoute="bank")
    record["stages"][stage_name] = {"status": raw_state}  # type: ignore[index]

    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(record, now=NOW)


def test_ocr_failure_accepts_only_the_exact_retained_producer_checkpoints() -> None:
    producer_record = _record(
        "OCR_FAILED",
        stages={
            "ingest": {"status": "ENQUEUED"},
            "ocr": {"status": "IN_PROGRESS"},
        },
    )
    projected = adapt_internal_document_status(producer_record, now=NOW)
    assert projected.safe_failure_code is SafeFailureCode.OCR_FAILED

    producer_record["stages"]["classify"] = {  # type: ignore[index]
        "status": "PENDING_HANDOFF"
    }
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(producer_record, now=NOW)


def test_stage_overall_mismatch_and_unknown_values_fail_closed() -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(
            _record("BANK_EXTRACTED", stages={"notify": {"status": "DONE"}}),
            now=NOW,
        )
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(_record("FUTURE_SUCCESS"), now=NOW)
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(
            _record("OCR", stages={"future-stage": {"status": "DONE"}}),
            now=NOW,
        )


@pytest.mark.parametrize("stage_name", ["bank-extract", "personal-extract"])
def test_hyphenated_persisted_extraction_stage_aliases_fail_closed(
    stage_name: str,
) -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(
            _record("OCR_COMPLETED", stages={stage_name: {"status": "ENQUEUED"}}),
            now=NOW,
        )


def test_unproduced_stage_state_field_alias_fails_closed() -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(
            _record("OCR", stages={"ocr": {"state": "IN_PROGRESS"}}),
            now=NOW,
        )


@pytest.mark.parametrize(
    "status,stage_name,raw_state,updates",
    [
        ("SUBMITTED", "ingest", "ENQUEUE_PENDING", {}),
        ("SUBMITTED", "ingest", "ENQUEUED", {}),
        ("SUBMITTED", "ingest", "ENQUEUE_FAILED", {}),
        ("OCR", "ocr", "IN_PROGRESS", {}),
        ("OCR_COMPLETED", "ocr", "COMPLETED", {}),
        ("OCR_COMPLETED", "classify", "ENQUEUED", {}),
        ("CLASSIFY_PENDING", "classify", "PENDING_HANDOFF", {}),
        ("CLASSIFY_COMPLETED", "classify", "COMPLETED", {}),
        (
            "OCR_COMPLETED",
            "bank_extract",
            "ENQUEUED",
            {"processing_domain": "bank", "documentRoute": "bank"},
        ),
        (
            "BANK_EXTRACTING",
            "bank_extract",
            "WRITING",
            {"processing_domain": "bank", "documentRoute": "bank"},
        ),
        (
            "BANK_EXTRACTED",
            "bank_extract",
            "COMPLETED",
            {"processing_domain": "bank", "documentRoute": "bank"},
        ),
        (
            "OCR_COMPLETED",
            "personal_extract",
            "ENQUEUED",
            {"processing_domain": "personal", "documentRoute": "personal"},
        ),
        (
            "PERSONAL_EXTRACTING",
            "personal_extract",
            "WRITING",
            {"processing_domain": "personal", "documentRoute": "personal"},
        ),
        (
            "PERSONAL_EXTRACTED",
            "personal_extract",
            "COMPLETED",
            {"processing_domain": "personal", "documentRoute": "personal"},
        ),
        (
            "BANK_EXTRACTED",
            "validate",
            "DONE",
            {"processing_domain": "bank", "documentRoute": "bank"},
        ),
    ],
)
def test_every_exact_nonterminal_writer_stage_token_projects(
    status: str,
    stage_name: str,
    raw_state: str,
    updates: dict[str, object],
) -> None:
    stages = {stage_name: {"status": raw_state}}
    required_stage = {
        "OCR": ("ocr", "IN_PROGRESS"),
        "OCR_COMPLETED": ("ocr", "COMPLETED"),
        "CLASSIFY_PENDING": ("classify", "PENDING_HANDOFF"),
        "CLASSIFY_COMPLETED": ("classify", "COMPLETED"),
        "BANK_EXTRACTING": ("bank_extract", "WRITING"),
        "BANK_EXTRACTED": ("bank_extract", "COMPLETED"),
        "PERSONAL_EXTRACTING": ("personal_extract", "WRITING"),
        "PERSONAL_EXTRACTED": ("personal_extract", "COMPLETED"),
    }.get(status)
    if required_stage is not None:
        required_name, required_state = required_stage
        stages.setdefault(required_name, {"status": required_state})
    projected = adapt_internal_document_status(
        _record(status, stages=stages, **updates),
        now=NOW,
    )
    assert projected.processing_condition in {
        ProcessingCondition.ACTIVE,
        ProcessingCondition.NOT_APPLICABLE,
    }


@pytest.mark.parametrize(
    "status,stages",
    [
        (
            "CREATED",
            {
                "persist": {
                    "status": "DONE",
                    "finalStatus": "COMPLETED",
                    "completedAt": UPDATED.isoformat(),
                }
            },
        ),
        ("UPLOADED", {"notify": {"status": "DONE"}}),
        ("OCR", {"ocr": {"status": "FAILED"}}),
        ("OCR_COMPLETED", {"ocr": {"status": "FAILED"}}),
        ("CLASSIFY_COMPLETED", {"classify": {"status": "ERROR"}}),
        (
            "BANK_EXTRACTED",
            {
                "bank-extract": {"status": "DONE"},
                "bank_extract": {"status": "FAILED"},
            },
        ),
        ("OCR_COMPLETED", {"ocr": {"status": "DONE", "state": "FAILED"}}),
    ],
)
def test_contradictory_stage_evidence_never_projects_success(
    status: str,
    stages: dict[str, object],
) -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(_record(status, stages=stages), now=NOW)


def test_reviewed_downstream_handoff_does_not_hide_ocr_success() -> None:
    projected = adapt_internal_document_status(
        _record(
            "OCR_COMPLETED",
            stages={
                "ocr": {"status": "COMPLETED"},
                "classify": {"status": "ENQUEUED"},
            },
        ),
        now=NOW,
    )
    assert projected.current_stage is PipelineStage.OCR
    assert projected.stage_state is StageState.SUCCEEDED


@pytest.mark.parametrize(
    "record",
    [
        _record(
            "PERSONAL_EXTRACTED",
            processing_domain="bank",
            documentRoute="bank",
        ),
        _record(
            "BANK_EXTRACTED",
            processing_domain="personal",
            documentRoute="platform",
        ),
        _record(
            "BANK_EXTRACTED",
            processing_domain="bank",
            documentRoute="bank",
            stages={"personal_extract": {"status": "DONE"}},
        ),
        _record(
            "BANK_EXTRACTED",
            processing_domain="bank",
            documentRoute="personal",
        ),
    ],
)
def test_processing_domain_route_stage_and_status_must_agree(
    record: dict[str, object],
) -> None:
    with pytest.raises(UnsupportedInternalState):
        adapt_internal_document_status(record, now=NOW)


def test_validate_done_projects_the_reachable_public_validate_stage() -> None:
    projected = adapt_internal_document_status(
        _record(
            "BANK_EXTRACTED",
            stages={
                "bank_extract": {"status": "COMPLETED"},
                "validate": {"status": "DONE"},
            },
        ),
        now=NOW,
    )
    assert projected.current_stage is PipelineStage.VALIDATE
    assert projected.stage_state is StageState.SUCCEEDED


def test_public_status_enums_are_exactly_source_reachable() -> None:
    assert {item.value for item in DocumentLifecycle} == {
        "UPLOAD_PENDING",
        "SUBMITTED",
        "PROCESSING",
        "COMPLETED",
        "FAILED",
    }
    assert {item.value for item in PipelineStage} == {
        "INGEST",
        "OCR",
        "CLASSIFY",
        "BANK_EXTRACT",
        "PERSONAL_EXTRACT",
        "VALIDATE",
        "TERMINAL",
    }
    assert {item.value for item in StageState} == {
        "PENDING",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
    }
    assert {item.value for item in ProcessingCondition} == {
        "ACTIVE",
        "NOT_APPLICABLE",
    }
    assert {item.value for item in FailureDisposition} == {"RETRYABLE", "TERMINAL"}
    assert {item.value for item in SafeFailureCode} == {
        "DOCUMENT_PROCESSING_FAILED",
        "OCR_FAILED",
        "ENQUEUE_FAILED",
    }


@pytest.mark.parametrize(
    "stage_state,payload",
    [
        (
            StageState.PENDING,
            {
                "lifecycle": DocumentLifecycle.UPLOAD_PENDING,
                "currentStage": PipelineStage.INGEST,
                "processingCondition": ProcessingCondition.ACTIVE,
            },
        ),
        (
            StageState.RUNNING,
            {
                "lifecycle": DocumentLifecycle.PROCESSING,
                "currentStage": PipelineStage.OCR,
                "processingCondition": ProcessingCondition.ACTIVE,
            },
        ),
        (
            StageState.SUCCEEDED,
            {
                "lifecycle": DocumentLifecycle.PROCESSING,
                "currentStage": PipelineStage.OCR,
                "processingCondition": ProcessingCondition.ACTIVE,
            },
        ),
        (
            StageState.FAILED,
            {
                "lifecycle": DocumentLifecycle.SUBMITTED,
                "currentStage": PipelineStage.INGEST,
                "processingCondition": ProcessingCondition.NOT_APPLICABLE,
                "failureDisposition": FailureDisposition.RETRYABLE,
                "safeFailureCode": SafeFailureCode.ENQUEUE_FAILED,
            },
        ),
    ],
)
def test_every_public_stage_state_is_constructible_from_a_reachable_projection(
    stage_state: StageState, payload: dict[str, object]
) -> None:
    response = DocumentStatusResponse(
        documentId=DOCUMENT_ID,
        stageState=stage_state,
        createdAt=CREATED,
        updatedAt=UPDATED,
        **payload,
    )
    assert response.stage_state is stage_state


@pytest.mark.parametrize("lifecycle", list(DocumentLifecycle))
def test_every_public_lifecycle_is_constructible(
    lifecycle: DocumentLifecycle,
) -> None:
    payload: dict[str, object] = {
        "documentId": DOCUMENT_ID,
        "createdAt": CREATED,
        "updatedAt": UPDATED,
    }
    if lifecycle is DocumentLifecycle.UPLOAD_PENDING:
        payload.update(
            currentStage=PipelineStage.INGEST,
            stageState=StageState.PENDING,
            processingCondition=ProcessingCondition.ACTIVE,
        )
    elif lifecycle is DocumentLifecycle.SUBMITTED:
        payload.update(
            currentStage=PipelineStage.INGEST,
            stageState=StageState.RUNNING,
            processingCondition=ProcessingCondition.ACTIVE,
        )
    elif lifecycle is DocumentLifecycle.PROCESSING:
        payload.update(
            currentStage=PipelineStage.OCR,
            stageState=StageState.RUNNING,
            processingCondition=ProcessingCondition.ACTIVE,
        )
    elif lifecycle is DocumentLifecycle.COMPLETED:
        payload.update(
            currentStage=PipelineStage.TERMINAL,
            stageState=StageState.SUCCEEDED,
            processingCondition=ProcessingCondition.NOT_APPLICABLE,
            terminalAt=UPDATED,
        )
    else:
        payload.update(
            currentStage=PipelineStage.TERMINAL,
            stageState=StageState.FAILED,
            processingCondition=ProcessingCondition.NOT_APPLICABLE,
            terminalAt=UPDATED,
            failureDisposition=FailureDisposition.TERMINAL,
            safeFailureCode=SafeFailureCode.DOCUMENT_PROCESSING_FAILED,
        )

    response = DocumentStatusResponse(lifecycle=lifecycle, **payload)
    assert response.lifecycle is lifecycle


_ALLOWED_LIFECYCLE_TRANSITIONS = frozenset(
    {
        (DocumentLifecycle.UPLOAD_PENDING, DocumentLifecycle.UPLOAD_PENDING),
        (DocumentLifecycle.UPLOAD_PENDING, DocumentLifecycle.SUBMITTED),
        (DocumentLifecycle.SUBMITTED, DocumentLifecycle.SUBMITTED),
        (DocumentLifecycle.SUBMITTED, DocumentLifecycle.PROCESSING),
        (DocumentLifecycle.PROCESSING, DocumentLifecycle.PROCESSING),
        (DocumentLifecycle.PROCESSING, DocumentLifecycle.COMPLETED),
        (DocumentLifecycle.PROCESSING, DocumentLifecycle.FAILED),
        (DocumentLifecycle.COMPLETED, DocumentLifecycle.COMPLETED),
        (DocumentLifecycle.FAILED, DocumentLifecycle.FAILED),
    }
)


@pytest.mark.parametrize(
    "previous,current",
    [
        (previous, current)
        for previous in DocumentLifecycle
        for current in DocumentLifecycle
    ],
)
def test_complete_public_lifecycle_transition_matrix(
    previous: DocumentLifecycle, current: DocumentLifecycle
) -> None:
    if (previous, current) in _ALLOWED_LIFECYCLE_TRANSITIONS:
        validate_lifecycle_transition(previous, current)
    else:
        with pytest.raises(UnsupportedInternalState):
            validate_lifecycle_transition(previous, current)


@pytest.mark.parametrize(
    "lifecycle,stage,state,condition",
    [
        (
            DocumentLifecycle.UPLOAD_PENDING,
            PipelineStage.OCR,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.SUBMITTED,
            PipelineStage.OCR,
            StageState.SUCCEEDED,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.PROCESSING,
            PipelineStage.INGEST,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.PROCESSING,
            PipelineStage.CLASSIFY,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.PROCESSING,
            PipelineStage.VALIDATE,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.PROCESSING,
            PipelineStage.OCR,
            StageState.FAILED,
            ProcessingCondition.ACTIVE,
        ),
        (
            DocumentLifecycle.PROCESSING,
            PipelineStage.OCR,
            StageState.RUNNING,
            ProcessingCondition.NOT_APPLICABLE,
        ),
    ],
)
def test_public_status_rejects_unreachable_nonterminal_combinations(
    lifecycle: DocumentLifecycle,
    stage: PipelineStage,
    state: StageState,
    condition: ProcessingCondition,
) -> None:
    with pytest.raises(ValidationError):
        DocumentStatusResponse(
            documentId=DOCUMENT_ID,
            lifecycle=lifecycle,
            currentStage=stage,
            stageState=state,
            processingCondition=condition,
            createdAt=CREATED,
            updatedAt=UPDATED,
        )


@pytest.mark.parametrize(
    "stage,lifecycle,state,condition",
    [
        (
            PipelineStage.INGEST,
            DocumentLifecycle.SUBMITTED,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.OCR,
            DocumentLifecycle.PROCESSING,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.CLASSIFY,
            DocumentLifecycle.PROCESSING,
            StageState.PENDING,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.BANK_EXTRACT,
            DocumentLifecycle.PROCESSING,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.PERSONAL_EXTRACT,
            DocumentLifecycle.PROCESSING,
            StageState.RUNNING,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.VALIDATE,
            DocumentLifecycle.PROCESSING,
            StageState.SUCCEEDED,
            ProcessingCondition.ACTIVE,
        ),
        (
            PipelineStage.TERMINAL,
            DocumentLifecycle.COMPLETED,
            StageState.SUCCEEDED,
            ProcessingCondition.NOT_APPLICABLE,
        ),
    ],
)
def test_every_public_pipeline_stage_is_constructible_from_a_reachable_projection(
    stage: PipelineStage,
    lifecycle: DocumentLifecycle,
    state: StageState,
    condition: ProcessingCondition,
) -> None:
    response = DocumentStatusResponse(
        documentId=DOCUMENT_ID,
        lifecycle=lifecycle,
        currentStage=stage,
        stageState=state,
        processingCondition=condition,
        createdAt=CREATED,
        updatedAt=UPDATED,
        terminalAt=UPDATED if lifecycle is DocumentLifecycle.COMPLETED else None,
    )
    assert response.current_stage is stage


@pytest.mark.parametrize("condition", list(ProcessingCondition))
def test_every_public_processing_condition_is_constructible(
    condition: ProcessingCondition,
) -> None:
    if condition is ProcessingCondition.NOT_APPLICABLE:
        response = DocumentStatusResponse(
            documentId=DOCUMENT_ID,
            lifecycle=DocumentLifecycle.COMPLETED,
            currentStage=PipelineStage.TERMINAL,
            stageState=StageState.SUCCEEDED,
            processingCondition=condition,
            createdAt=CREATED,
            updatedAt=UPDATED,
            terminalAt=UPDATED,
        )
    else:
        response = DocumentStatusResponse(
            documentId=DOCUMENT_ID,
            lifecycle=DocumentLifecycle.PROCESSING,
            currentStage=PipelineStage.OCR,
            stageState=StageState.RUNNING,
            processingCondition=condition,
            createdAt=CREATED,
            updatedAt=UPDATED,
        )
    assert response.processing_condition is condition


def _reconciliation(state: LedgerState) -> ReconciliationResponse:
    kwargs: dict[str, object] = {
        "operation": OperationKind.BATCH_CREATE,
        "ledgerState": state,
        "createdAt": CREATED,
        "updatedAt": UPDATED,
        "expiresAt": CREATED + timedelta(days=30),
    }
    if state is LedgerState.SUCCEEDED:
        kwargs["completedAt"] = UPDATED
        kwargs["durableResponse"] = {
            "schemaVersion": "scanalyze.batch-create-result.v1",
            "contractVersion": CONTRACT_VERSION,
            "operation": "batches.create",
            "batchId": "b" * 32,
            "status": "OPEN",
            "createdAt": CREATED,
        }
    elif state is LedgerState.FAILED_RETRYABLE:
        kwargs["failureCode"] = ReconciliationFailureCode.CREATE_FAILED_RETRYABLE
    elif state is LedgerState.FAILED_TERMINAL:
        kwargs.update(
            failureCode=ReconciliationFailureCode.CREATE_FAILED_TERMINAL,
            completedAt=UPDATED,
        )
    elif state is LedgerState.UNKNOWN_OR_QUARANTINED:
        kwargs.update(
            failureCode=ReconciliationFailureCode.UNKNOWN_WRITE_OUTCOME,
            completedAt=UPDATED,
        )
    elif state is LedgerState.EXPIRED:
        expiry = CREATED + timedelta(days=30)
        kwargs.update(
            failureCode=ReconciliationFailureCode.OPERATION_EXPIRED,
            completedAt=expiry,
            updatedAt=expiry,
            expiresAt=expiry,
        )
    return ReconciliationResponse(**kwargs)


@pytest.mark.parametrize("state", list(LedgerState))
def test_every_reconciliation_state_has_exact_timestamp_semantics(
    state: LedgerState,
) -> None:
    response = _reconciliation(state)
    assert response.ledger_state is state
    if state is LedgerState.FAILED_RETRYABLE:
        assert response.completed_at is None
    if state is LedgerState.EXPIRED:
        assert response.updated_at >= response.expires_at


def test_expired_reconciliation_can_preserve_an_earlier_terminal_completion() -> None:
    expires_at = CREATED + timedelta(days=30)
    response = ReconciliationResponse(
        operation=OperationKind.DOCUMENT_CREATE,
        ledgerState=LedgerState.EXPIRED,
        failureCode=ReconciliationFailureCode.OPERATION_EXPIRED,
        createdAt=CREATED,
        completedAt=UPDATED,
        expiresAt=expires_at,
        updatedAt=expires_at + timedelta(seconds=1),
    )

    assert response.created_at <= response.completed_at < response.expires_at
    assert response.expires_at <= response.updated_at


@pytest.mark.parametrize("code", [ErrorCode.RATE_LIMITED, ErrorCode.SERVICE_UNAVAILABLE])
def test_retry_after_is_allowed_for_the_exact_two_public_errors(
    code: ErrorCode,
) -> None:
    _status, envelope = public_error(
        code,
        "correlation-0001",
        details=ErrorDetails(retryAfterSeconds=30),
    )
    assert envelope.details is not None
    assert envelope.details.retry_after_seconds == 30


@pytest.mark.parametrize(
    "code",
    [
        code
        for code in ErrorCode
        if code not in {ErrorCode.RATE_LIMITED, ErrorCode.SERVICE_UNAVAILABLE}
    ],
)
def test_retry_after_is_rejected_for_every_other_public_error(code: ErrorCode) -> None:
    with pytest.raises(JourneyContractError):
        public_error(
            code,
            "correlation-0001",
            details=ErrorDetails(retryAfterSeconds=30),
        )


def test_bank_projection_remasks_identifiers_and_ignores_nested_additions() -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    full_account = "1111222233334444"
    full_clabe = "123456789" + "012345678"
    artifact["account"]["numberMasked"] = "0000111122223333"
    artifact["account"]["clabeMasked"] = "000011112" + "222333344"
    artifact["bank"]["name"] = f"Bank {full_account}"
    artifact["account"]["holder"] = f"Holder {full_clabe}"
    artifact["transactions"][0]["description"] = (
        "Transfer 1111-2222-3333-4444"
    )
    artifact["transactions"][0]["reference"] = f"Ref {full_clabe}"
    artifact["summaryText"] = f"Account {full_account}"
    artifact["bank"]["futureProducerField"] = "not-public"
    artifact["transactions"][0]["futureProducerField"] = "not-public"
    artifact["transactions"][0]["category"] = "future-category"

    result = project_bank_statement_result(artifact, document_id=DOCUMENT_ID)
    assert result.data.account.number_masked == "****3333"
    assert result.data.account.clabe_masked == "****3344"
    assert result.data.bank.name == "Bank ****4444"
    assert result.data.account.holder == "Holder ****5678"
    assert result.data.transactions[0].description == "Transfer ****4444"
    assert result.data.transactions[0].reference == "Ref ****5678"
    assert result.data.summary_text == "Account ****4444"
    assert result.data.transactions[0].category is contract.TransactionCategory.OTHER
    serialized = result.model_dump_json(by_alias=True)
    assert "0000111122223333" not in serialized
    assert "000011112" + "222333344" not in serialized
    assert full_account not in serialized
    assert full_clabe not in serialized
    assert "1111-2222-3333-4444" not in serialized
    assert "futureProducerField" not in serialized


@pytest.mark.parametrize("digit_count", range(8, 19))
@pytest.mark.parametrize("separator", ["", "-----", "\u2003" * 6, "•" * 7])
def test_bank_projection_masks_every_bounded_identifier_across_public_text(
    digit_count: int, separator: str
) -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    digits = ("123456789" + "012345678")[:digit_count]
    candidate = separator.join(digits)
    artifact["bank"]["name"] = f"Bank {candidate}"
    artifact["account"]["holder"] = f"Holder {candidate}"
    artifact["transactions"][0]["description"] = f"Transfer {candidate}"
    artifact["transactions"][0]["reference"] = f"Ref {candidate}"
    artifact["summaryText"] = f"Summary {candidate}"

    result = project_bank_statement_result(artifact, document_id=DOCUMENT_ID)
    expected_suffix = f"****{digits[-4:]}"

    assert result.data.bank.name == f"Bank {expected_suffix}"
    assert result.data.account.holder == f"Holder {expected_suffix}"
    assert result.data.transactions[0].description == f"Transfer {expected_suffix}"
    assert result.data.transactions[0].reference == f"Ref {expected_suffix}"
    assert result.data.summary_text == f"Summary {expected_suffix}"
    assert candidate not in result.model_dump_json(by_alias=True)


def test_bank_projection_does_not_treat_unicode_digits_as_ascii_identifiers() -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    unicode_digits = "١٢٣٤٥٦٧٨"
    artifact["summaryText"] = f"Reference {unicode_digits}"

    result = project_bank_statement_result(artifact, document_id=DOCUMENT_ID)

    assert result.data.summary_text == f"Reference {unicode_digits}"


@pytest.mark.parametrize("source_field", ["number", "clabe"])
@pytest.mark.parametrize("digit_count", [7, 19])
def test_bank_projection_masks_exact_source_identifier_variants_outside_generic_range(
    source_field: str, digit_count: int
) -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    digits = "1234567890123456789"[:digit_count]
    candidate = "-".join(digits)
    artifact["account"][source_field] = candidate
    artifact["account"][f"{source_field}Masked"] = None
    artifact["summaryText"] = f"Source {candidate}"

    result = project_bank_statement_result(artifact, document_id=DOCUMENT_ID)

    assert result.data.summary_text == f"Source ****{digits[-4:]}"
    assert candidate not in result.model_dump_json(by_alias=True)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda artifact: artifact["balances"].__setitem__("opening", "100.0"),
        lambda artifact: artifact.__setitem__("overallConfidence", "99"),
        lambda artifact: artifact["transactions"][0].__setitem__("amount", "25"),
        lambda artifact: artifact.__setitem__("generatedAt", 1_786_200_000),
    ],
)
def test_bank_projection_rejects_type_coercion(mutate: object) -> None:
    artifact = deepcopy(_bank_artifact(DOCUMENT_ID))
    mutate(artifact)  # type: ignore[operator]
    with pytest.raises(MalformedInternalResult):
        project_bank_statement_result(artifact, document_id=DOCUMENT_ID)


def test_bank_projection_rejects_inverted_period() -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    artifact["statement"] = {
        "periodStart": "2026-08-01",
        "periodEnd": "2026-07-01",
    }
    with pytest.raises((MalformedInternalResult, ValidationError)):
        project_bank_statement_result(artifact, document_id=DOCUMENT_ID)


def test_bank_projection_rejects_identifier_hidden_in_provenance() -> None:
    artifact = _bank_artifact(DOCUMENT_ID)
    artifact["prompt_version"] = "1.2.3+1111222233334444"

    with pytest.raises(MalformedInternalResult):
        project_bank_statement_result(artifact, document_id=DOCUMENT_ID)
